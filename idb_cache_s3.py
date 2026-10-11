"""Per-generation S3 transport; selections remain the exact consumer manifest.

References are producer-only discovery hints. Objects and selection receipts are
immutable. Remote deletion is deliberately separate from local cache pruning.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

from ci_s3_cache import parse_endpoint
from idb_cache import (
    _atomic_copy,
    _contained_path,
    _parse_selection,
    _tag_root,
    _validate_manifest,
    _verify_generation_root,
    cache_key,
    verify_selection,
)
from idb_cache_leases import _path as lease_path
from idb_cache_leases import _read as read_lease
from idb_cache_leases import lease_reference, require_lease, validate_lease
from idb_cache_locks import tag_lock
from idb_cache_selection import SELECTION_ENTRY_KEYS, generation_selection
from release_workflow_lib.hashing import canonical_json_bytes, normalized_sha256, sha256_bytes, sha256_file

BUCKET = "actions-cache-goldsrc-vibesignatures"
METADATA_LIMIT = 16 * 1024 * 1024
PART_SIZE = 64 * 1024 * 1024
COPY_BUFFER_SIZE = 1024 * 1024


class S3Objects:
    """Small SDK adapter. Only absence is a miss; authorization/network errors fail."""

    def __init__(self, client, bucket=BUCKET):
        self.client, self.bucket = client, bucket

    @staticmethod
    def _status(error):
        return error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")

    def _head(self, key):
        from botocore.exceptions import ClientError

        try:
            return self.client.head_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            if self._status(exc) == 404:
                return None
            raise

    def exists(self, key):
        return self._head(key) is not None

    def read(self, key, *, required=True):
        from botocore.exceptions import ClientError

        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            if not required and self._status(exc) == 404:
                return None
            raise
        with response["Body"] as body:
            raw = body.read(METADATA_LIMIT + 1)
        if len(raw) > METADATA_LIMIT:
            raise ValueError("S3 cache metadata exceeds size limit")
        return raw

    def download(self, key, path):
        from boto3.s3.transfer import TransferConfig

        # SDK managed downloads retry interrupted transfers without buffering an IDB.
        self.client.download_file(self.bucket, key, str(path), Config=TransferConfig(max_concurrency=2))

    def put(self, key, path, *, immutable=True):
        from botocore.exceptions import BotoCoreError, ClientError

        digest, size = sha256_file(path), path.stat().st_size

        def verify_existing(head):
            if head is None or head.get("Metadata", {}).get("sha256") != digest or head["ContentLength"] != size:
                raise ValueError("Immutable S3 cache object conflict or failed publication")

        if immutable:
            head = self._head(key)
            if head is not None:
                verify_existing(head)
                return
        args = {"Bucket": self.bucket, "Key": key}
        condition = {"IfNoneMatch": "*"} if immutable else {}
        metadata = {"sha256": digest}
        try:
            with path.open("rb") as source:
                if size <= PART_SIZE:
                    self.client.put_object(**args, **condition, Body=source, Metadata=metadata)
                else:
                    upload = self.client.create_multipart_upload(**args, Metadata=metadata)["UploadId"]
                    try:
                        parts = []
                        # Stay below S3's 10,000-part limit for large generations.
                        chunk_size = max(PART_SIZE, (size + 9998) // 9999)
                        while block := source.read(chunk_size):
                            number = len(parts) + 1
                            response = self.client.upload_part(**args, UploadId=upload, PartNumber=number, Body=block)
                            parts.append({"PartNumber": number, "ETag": response["ETag"]})
                        self.client.complete_multipart_upload(
                            **args, **condition, UploadId=upload, MultipartUpload={"Parts": parts}
                        )
                    except BaseException:
                        try:
                            self.client.abort_multipart_upload(**args, UploadId=upload)
                        except (BotoCoreError, ClientError):
                            print("IDB S3 multipart cleanup failed; preserve the original upload failure", flush=True)
                        raise
        except ClientError as exc:
            if not immutable or self._status(exc) != 412:
                raise
            # A concurrent identical publisher is harmless; never overwrite a conflict.
        verify_existing(self._head(key))


def transport_from_environment(repository):
    import boto3
    from botocore.config import Config

    endpoint = os.environ["S3_ENDPOINT_URL"]
    parse_endpoint(endpoint)
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="us-east-1",
        aws_access_key_id=os.environ["S3_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["S3_SECRET_ACCESS_KEY"],
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"mode": "standard", "total_max_attempts": 4},
            connect_timeout=15,
            read_timeout=120,
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )
    return GenerationTransport(S3Objects(client), repository)


def _json(raw):
    document = json.loads(raw)
    if canonical_json_bytes(document) != raw:
        raise ValueError("S3 cache metadata must be canonical JSON")
    return document


class GenerationTransport:
    def __init__(self, objects, repository):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("Invalid S3 cache repository")
        self.objects = objects
        self.repository = repository.lower()
        self.prefix = f"gsvibe-idb-objects-v1/{sha256_bytes(self.repository.encode())}"

    def object_key(self, selection):
        selection = _parse_selection(canonical_json_bytes(selection))
        return (
            f"{self.prefix}/generations/{selection['cache_key']}/"
            f"{selection['generation']}/{selection['manifest_sha256']}.tar.gz"
        )

    def reference_key(self, identity):
        return f"{self.prefix}/references/{cache_key(identity)}.json"

    def receipt_key(self, digest):
        normalized_sha256(digest, "selection digest")
        return f"{self.prefix}/selections/{digest}.json"

    def _put_json(self, key, document, *, immutable=True):
        with tempfile.TemporaryDirectory(prefix="idb-metadata-") as directory:
            path = Path(directory) / "metadata.json"
            path.write_bytes(canonical_json_bytes(document))
            self.objects.put(key, path, immutable=immutable)

    def _validate_document(self, document, digest):
        if sha256_bytes(canonical_json_bytes(document)) != digest:
            raise ValueError("S3 cache selection digest mismatch")
        if document.get("schema_version") != 3 or document.get("cache_mode") != "warm":
            raise ValueError("Unsupported S3 cache selection")
        lease = validate_lease(document["lease"])
        if lease["repository"].lower() != self.repository:
            raise ValueError("S3 cache selection repository mismatch")
        if not isinstance(document.get("entries"), list) or not document["entries"]:
            raise ValueError("S3 cache selection must contain entries")
        seen = set()
        for entry in document["entries"]:
            if not isinstance(entry, dict) or set(entry) != SELECTION_ENTRY_KEYS or len(entry["binaries"]) != 1:
                raise ValueError("S3 cache selection requires one binary per entry")
            selection = _parse_selection(canonical_json_bytes(generation_selection(entry)))
            key = (entry["tag"], entry["cache_key"])
            if key in seen:
                raise ValueError("Duplicate S3 cache selection entry")
            seen.add(key)
            self.object_key(selection)

    @staticmethod
    def _check_manifest(manifest, selection, identity=None):
        if (
            manifest["cache_key"] != selection["cache_key"]
            or manifest["tag"] != selection["tag"]
            or manifest["generation"] != selection["generation"]
        ):
            raise ValueError("S3 generation binding mismatch")
        if identity is not None and manifest["identity"] != identity:
            raise ValueError("S3 generation identity mismatch")

    def fetch(self, persisted_root, selection, *, identity=None):
        key = self.object_key(selection)
        with tag_lock(persisted_root, selection["tag"]):
            tag = _tag_root(persisted_root, selection["tag"], create=True)
            target = _contained_path(tag, f"generations/{selection['generation']}")
            if target.exists():
                manifest = verify_selection(persisted_root=persisted_root, selection=selection)
                self._check_manifest(manifest, selection, identity)
                return
            target.parent.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".transport-", dir=target.parent) as directory:
                stage = Path(directory)
                archive_path, incoming = stage / "generation.tar.gz", stage / "generation"
                incoming.mkdir()
                self.objects.download(key, archive_path)
                with tarfile.open(archive_path, "r|gz") as archive:
                    first = archive.next()
                    if (
                        first is None
                        or first.name != "manifest.json"
                        or not first.isreg()
                        or first.size > METADATA_LIMIT
                        or first.issparse()
                    ):
                        raise ValueError("Invalid S3 generation archive manifest")
                    raw = archive.extractfile(first).read()
                    if sha256_bytes(raw) != selection["manifest_sha256"]:
                        raise ValueError("S3 generation manifest digest mismatch")
                    manifest = _validate_manifest(_json(raw), raw)
                    self._check_manifest(manifest, selection, identity)
                    (incoming / "manifest.json").write_bytes(raw)
                    expected = {record["path"]: record for record in manifest["files"]}
                    seen = set()
                    while member := archive.next():
                        record = expected.get(member.name)
                        if (
                            record is None
                            or member.name in seen
                            or not member.isreg()
                            or member.issparse()
                            or member.size != record["size"]
                        ):
                            raise ValueError("Invalid or undeclared S3 generation archive member")
                        destination = _contained_path(incoming, member.name)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        with archive.extractfile(member) as source, destination.open("xb") as output:
                            shutil.copyfileobj(source, output, COPY_BUFFER_SIZE)
                        seen.add(member.name)
                    if seen != set(expected):
                        raise ValueError("Incomplete S3 generation archive")
                _verify_generation_root(incoming, expected_generation=selection["generation"])
                os.replace(incoming, target)
                print(
                    f"IDB S3 downloaded: generation={selection['generation']}; bytes={archive_path.stat().st_size}",
                    flush=True,
                )

    def prefetch(self, persisted_root, identity):
        raw = self.objects.read(self.reference_key(identity), required=False)
        if raw is None:
            return None
        selection = _parse_selection(raw)
        if selection["cache_key"] != cache_key(identity) or selection["tag"] != identity["tag"]:
            raise ValueError("S3 discovery reference identity mismatch")
        if not self.objects.exists(self.object_key(selection)):
            # An evicted payload is a producer miss, never a consumer fallback.
            return None
        self.fetch(persisted_root, selection, identity=identity)
        return selection

    def _upload_generation(self, persisted_root, selection, manifest):
        key = self.object_key(selection)
        if self.objects.exists(key):
            return
        root = _contained_path(_tag_root(persisted_root, selection["tag"]), f"generations/{selection['generation']}")
        with tempfile.TemporaryDirectory(prefix="idb-upload-") as directory:
            path = Path(directory) / "generation.tar.gz"
            with (
                path.open("wb") as output,
                gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=1) as compressed,
                tarfile.open(fileobj=compressed, mode="w|") as archive,
            ):
                for relative in ["manifest.json", *(record["path"] for record in manifest["files"])]:
                    source = _contained_path(root, relative, require_file=True)
                    info = tarfile.TarInfo(relative)
                    info.size, info.mode = source.stat().st_size, 0o644
                    with source.open("rb") as content:
                        archive.addfile(info, content)
            self.objects.put(key, path)
            print(f"IDB S3 uploaded: generation={selection['generation']}; bytes={path.stat().st_size}", flush=True)

    def publish(self, persisted_root, document):
        digest = sha256_bytes(canonical_json_bytes(document))
        self._validate_document(document, digest)
        leases = {}
        for entry in document["entries"]:
            with tag_lock(persisted_root, entry["tag"]):
                tag = _tag_root(persisted_root, entry["tag"])
                require_lease(
                    tag_root=tag, lease=document["lease"], selection_sha256=digest, reference=lease_reference(entry)
                )
                selection = generation_selection(entry)
                manifest = verify_selection(persisted_root=persisted_root, selection=selection)
                if manifest["identity"]["binaries"] != entry["binaries"]:
                    raise ValueError("S3 selection binary mismatch")
                self._upload_generation(persisted_root, selection, manifest)
                self._put_json(self.reference_key(manifest["identity"]), selection, immutable=False)
                leases[entry["tag"]] = read_lease(lease_path(tag, document["lease"]), entry["tag"])
        # Commit record comes last. Consumers never consult mutable discovery references.
        self._put_json(
            self.receipt_key(digest),
            {
                "schema_version": 1,
                "selection_sha256": digest,
                "leases": [leases[tag] for tag in sorted(leases)],
            },
        )

    def restore(self, persisted_root, document, digest):
        self._validate_document(document, digest)
        receipt = _json(self.objects.read(self.receipt_key(digest)))
        if (
            not isinstance(receipt, dict)
            or set(receipt) != {"schema_version", "selection_sha256", "leases"}
            or receipt["schema_version"] != 1
            or receipt["selection_sha256"] != digest
        ):
            raise ValueError("Invalid S3 selection publication receipt")
        tags = {entry["tag"] for entry in document["entries"]}
        if len(receipt["leases"]) != len(tags) or {record["tag"] for record in receipt["leases"]} != tags:
            raise ValueError("S3 selection lease coverage mismatch")
        # Verify the original producer lease records before installing any payload.
        with tempfile.TemporaryDirectory(prefix="idb-receipt-") as directory:
            staged = Path(directory)
            for record in receipt["leases"]:
                tag = _tag_root(staged, record["tag"], create=True)
                lease_path(tag, document["lease"], create=True).write_bytes(canonical_json_bytes(record))
            for entry in document["entries"]:
                require_lease(
                    tag_root=_tag_root(staged, entry["tag"]),
                    lease=document["lease"],
                    selection_sha256=digest,
                    reference=lease_reference(entry),
                )
            for entry in document["entries"]:
                self.fetch(persisted_root, generation_selection(entry))
            for tag_name in sorted(tags):
                with tag_lock(persisted_root, tag_name):
                    tag = _tag_root(persisted_root, tag_name)
                    source = lease_path(_tag_root(staged, tag_name), document["lease"])
                    target = lease_path(tag, document["lease"], create=True)
                    if target.exists() and target.read_bytes() != source.read_bytes():
                        raise ValueError("Existing local lease conflicts with S3 publication")
                    _atomic_copy(source, target)
