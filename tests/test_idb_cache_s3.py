import copy
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from idb_cache import publish_generation, verify_selection
from idb_cache_leases import new_lease
from idb_cache_s3 import GenerationTransport, S3Objects
from idb_cache_selection import restore_selection_entries
from idb_cache_workflow import SelectedBinaryGroup
from release_workflow_lib.hashing import canonical_json_bytes, sha256_bytes
from tests.test_idb_cache import cache_fixture, pin_document


class MemoryObjects:
    def __init__(self):
        self.objects = {}
        self.reads = []
        self.writes = []
        self.fail_key = None

    def exists(self, key):
        return key in self.objects

    def read(self, key, *, required=True):
        self.reads.append(key)
        if key not in self.objects and required:
            raise ValueError("Missing object")
        return self.objects.get(key)

    def download(self, key, path):
        path.write_bytes(self.read(key))

    def put(self, key, path, *, immutable=True):
        if key == self.fail_key:
            raise ValueError("injected upload failure")
        raw = path.read_bytes()
        if immutable and key in self.objects:
            if raw != self.objects[key]:
                raise ValueError("Immutable object conflict")
            return
        self.objects[key] = raw
        self.writes.append(key)


class GenerationTransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.workspace, self.persisted, self.binary, self.identity = cache_fixture(self.root)
        self.store = MemoryObjects()
        self.transport = GenerationTransport(self.store, "owner/repo")
        self.selection = publish_generation(
            persisted_root=self.persisted, identity=self.identity, workspace_root=self.workspace, run_id="1", attempt=1
        )
        self.entry = {
            **{key: value for key, value in self.selection.items() if key != "schema_version"},
            "platform": "windows",
            "binaries": self.identity["binaries"],
        }
        self.document = {
            "schema_version": 3,
            "cache_mode": "warm",
            "entries": [self.entry],
            "lease": new_lease(repository="owner/repo", run_id="1", attempt=1),
        }
        self.digest = pin_document(self.persisted, self.document)

    def publish(self):
        self.transport.publish(self.persisted, self.document)

    def test_subset_download_and_exact_restore_with_lease(self):
        # An unselected generation in the same store must not travel over the wire.
        other_identity = copy.deepcopy(self.identity)
        other_identity["tag"] = "other-1"
        publish_generation(
            persisted_root=self.persisted, identity=other_identity, workspace_root=self.workspace, run_id="2", attempt=1
        )
        self.publish()
        archives = [key for key in self.store.objects if key.endswith(".tar.gz")]
        self.assertEqual(1, len(archives))
        consumer = self.root / "linux-consumer"
        self.transport.restore(consumer, self.document, self.digest)
        self.assertEqual(1, sum(key.endswith(".tar.gz") for key in self.store.reads))
        self.assertFalse((consumer / "idb-cache-v3" / "other-1").exists())
        Path(f"{self.binary}.i64").write_bytes(b"consumer edits")
        restore_selection_entries(
            entries=[self.entry],
            groups=(SelectedBinaryGroup("game-1", "windows", self.workspace, tuple(self.identity["binaries"])),),
            persisted_root=consumer,
            lease=self.document["lease"],
            selection_sha256=self.digest,
        )
        self.assertEqual(b"primary-idb", Path(f"{self.binary}.i64").read_bytes())

    def test_republish_reuses_payload_and_new_producer_fetches_only_identity(self):
        self.publish()
        self.publish()
        self.assertEqual(1, sum(key.endswith(".tar.gz") for key in self.store.writes))
        target = self.root / "next-producer"
        selected = self.transport.prefetch(target, self.identity)
        self.assertEqual(self.selection, selected)
        self.assertEqual(self.identity, verify_selection(persisted_root=target, selection=selected)["identity"])
        changed = copy.deepcopy(self.identity)
        changed["ida_runtime"]["kernel_version"] = "9.4"
        count = len(self.store.reads)
        self.assertIsNone(self.transport.prefetch(target, changed))
        self.assertEqual(1, len(self.store.reads) - count)

    def test_digest_mismatch_rejected_before_network(self):
        self.publish()
        with self.assertRaises(ValueError):
            self.transport.restore(self.root / "consumer", self.document, "a" * 64)
        self.assertEqual([], self.store.reads)

    def test_corrupt_or_missing_payload_never_installed(self):
        self.publish()
        key = self.transport.object_key(self.selection)
        for raw in (b"not an archive", None):
            with self.subTest(raw=raw):
                if raw is None:
                    self.store.objects.pop(key, None)
                else:
                    self.store.objects[key] = raw
                target = self.root / "consumer"
                with self.assertRaises((ValueError, tarfile.TarError)):
                    self.transport.restore(target, self.document, self.digest)
                self.assertFalse(
                    (target / "idb-cache-v3" / "game-1" / "generations" / self.selection["generation"]).exists()
                )

    def test_archive_cannot_escape_staging(self):
        self.publish()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            info = tarfile.TarInfo("../escaped")
            info.size = 3
            archive.addfile(info, io.BytesIO(b"bad"))
        self.store.objects[self.transport.object_key(self.selection)] = stream.getvalue()
        with self.assertRaises(ValueError):
            self.transport.restore(self.root / "consumer", self.document, self.digest)
        self.assertEqual([], list(self.root.rglob("escaped")))

    def test_failed_upload_publishes_no_selection_receipt(self):
        self.store.fail_key = self.transport.object_key(self.selection)
        with self.assertRaisesRegex(ValueError, "injected"):
            self.publish()
        self.assertNotIn(self.transport.receipt_key(self.digest), self.store.objects)
        self.assertNotIn(self.transport.reference_key(self.identity), self.store.objects)

    def test_foreign_or_tampered_lease_rejected(self):
        self.publish()
        import json

        key = self.transport.receipt_key(self.digest)
        receipt = json.loads(self.store.objects[key])
        receipt["leases"][0]["selection_sha256"] = "a" * 64
        self.store.objects[key] = canonical_json_bytes(receipt)
        with self.assertRaises(ValueError):
            self.transport.restore(self.root / "consumer", self.document, self.digest)

    def test_reference_must_bind_requested_identity(self):
        self.publish()
        changed = copy.deepcopy(self.identity)
        changed["ida_runtime"]["kernel_version"] = "9.4"
        self.store.objects[self.transport.reference_key(changed)] = canonical_json_bytes(self.selection)
        with self.assertRaises(ValueError):
            self.transport.prefetch(self.root / "next-producer", changed)
        self.assertFalse(any(key.endswith(".tar.gz") for key in self.store.reads))

    def test_repository_namespace_isolation(self):
        other = GenerationTransport(self.store, "other/repo")
        self.assertNotEqual(self.transport.object_key(self.selection), other.object_key(self.selection))
        self.assertEqual(
            self.transport.object_key(self.selection),
            GenerationTransport(self.store, "Owner/Repo").object_key(self.selection),
        )

    def test_evicted_object_is_only_a_producer_miss(self):
        self.publish()
        del self.store.objects[self.transport.object_key(self.selection)]
        self.assertIsNone(self.transport.prefetch(self.root / "producer", self.identity))
        with self.assertRaises(ValueError):
            self.transport.restore(self.root / "consumer", self.document, self.digest)

    def test_prefetched_hit_skips_warming_while_missing_sibling_warms(self):
        from idb_cache import build_binary_identity
        from idb_cache_selection import prepare_selection_entries
        from tests.test_support import write_pe32
        from warmup_memory import ProducerMemoryOwner

        self.publish()
        write_pe32(self.workspace / "client" / "client.dll", b"client")
        client = build_binary_identity(
            workspace_root=self.workspace, module="client", platform="windows", relative_path="client/client.dll"
        )
        identity = {**self.identity, "binaries": [client, *self.identity["binaries"]]}
        group = SelectedBinaryGroup("game-1", "windows", self.workspace, tuple(identity["binaries"]))
        target = self.root / "next-producer"
        warmed = []

        def warm(**kwargs):
            for binary in kwargs["identity"]["binaries"]:
                warmed.append(binary["module"])
                Path(f"{self.workspace / binary['path']}.i64").write_bytes(b"new-idb")

        with patch("idb_cache_selection.warm_group", side_effect=warm):
            entries = prepare_selection_entries(
                groups=(group,),
                identities={("game-1", "windows"): identity},
                persisted_root=target,
                run_id="2",
                attempt=1,
                ida_python_executable="unused",
                max_concurrency=2,
                worker_timeout_seconds=1,
                producer_memory=ProducerMemoryOwner(None),
                lease=new_lease(repository="owner/repo", run_id="2", attempt=1),
                remote_cache=self.transport,
            )
        self.assertEqual(["client"], warmed)
        self.assertEqual(
            self.selection["generation"],
            next(entry["generation"] for entry in entries if entry["binaries"][0]["module"] == "engine"),
        )

    def test_consumer_ignores_changed_discovery_pointer(self):
        self.publish()
        self.store.objects[self.transport.reference_key(self.identity)] = b"broken hint"
        self.transport.restore(self.root / "consumer", self.document, self.digest)
        self.assertNotIn(self.transport.reference_key(self.identity), self.store.reads)

    def test_valid_archive_with_tampering_duplicates_or_links_is_rejected(self):
        self.publish()
        key = self.transport.object_key(self.selection)
        with tarfile.open(fileobj=io.BytesIO(self.store.objects[key]), mode="r:gz") as archive:
            original = [(member, archive.extractfile(member).read()) for member in archive]
        for mutation in ("payload", "duplicate", "link", "missing", "manifest"):
            with self.subTest(mutation=mutation):
                members = copy.deepcopy(original)
                if mutation == "payload":
                    info, raw = members[-1]
                    members[-1] = (info, b"x" * len(raw))
                elif mutation == "duplicate":
                    members.append(members[-1])
                elif mutation == "link":
                    members[-1][0].type = tarfile.SYMTYPE
                    members[-1][0].linkname = "../../escaped"
                    members[-1][0].size = 0
                elif mutation == "missing":
                    members.pop()
                else:
                    info, raw = members[0]
                    members[0] = (info, b" " * len(raw))
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                    for info, raw in members:
                        archive.addfile(info, io.BytesIO(raw))
                self.store.objects[key] = stream.getvalue()
                target = self.root / mutation
                with self.assertRaises(ValueError):
                    self.transport.restore(target, self.document, self.digest)
                self.assertFalse(
                    (target / "idb-cache-v3" / "game-1" / "generations" / self.selection["generation"]).exists()
                )


class S3ObjectsTests(unittest.TestCase):
    def setUp(self):
        from botocore.exceptions import ClientError

        self.client = Mock()
        self.objects = S3Objects(self.client, "bucket")
        self.missing = ClientError(
            {"Error": {"Code": "404"}, "ResponseMetadata": {"HTTPStatusCode": 404}}, "HeadObject"
        )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "object"
        self.path.write_bytes(b"payload")
        self.head = {"ContentLength": 7, "Metadata": {"sha256": sha256_bytes(b"payload")}}

    def test_existing_identical_object_does_not_upload(self):
        self.client.head_object.return_value = self.head
        self.objects.put("key", self.path)
        self.client.put_object.assert_not_called()

    def test_existing_conflicting_object_cannot_be_overwritten(self):
        self.client.head_object.return_value = {**self.head, "ContentLength": 8}
        with self.assertRaisesRegex(ValueError, "conflict"):
            self.objects.put("key", self.path)
        self.client.put_object.assert_not_called()

    def test_conditional_put_and_publication_verification(self):
        self.client.head_object.side_effect = [self.missing, self.head]
        self.objects.put("key", self.path)
        self.assertEqual("*", self.client.put_object.call_args.kwargs["IfNoneMatch"])
        self.assertEqual(2, self.client.head_object.call_count)

    def test_forbidden_is_not_a_cache_miss(self):
        from botocore.exceptions import ClientError

        error = ClientError(
            {"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 403}}, "GetObject"
        )
        self.client.get_object.side_effect = error
        with self.assertRaises(ClientError):
            self.objects.read("key", required=False)
        self.client.head_object.side_effect = error
        with self.assertRaises(ClientError):
            self.objects.exists("key")

    def test_multipart_completion_is_conditional_and_failure_aborts(self):
        self.client.head_object.side_effect = [self.missing, self.head]
        self.client.create_multipart_upload.return_value = {"UploadId": "upload"}
        self.client.upload_part.return_value = {"ETag": "etag"}
        with patch("idb_cache_s3.PART_SIZE", 4):
            self.objects.put("key", self.path)
        self.assertEqual(2, self.client.upload_part.call_count)
        self.assertEqual("*", self.client.complete_multipart_upload.call_args.kwargs["IfNoneMatch"])
        self.client.head_object.side_effect = self.missing
        self.client.upload_part.side_effect = OSError("injected interrupted transfer")
        with patch("idb_cache_s3.PART_SIZE", 4), self.assertRaises(OSError):
            self.objects.put("other", self.path)
        self.client.abort_multipart_upload.assert_called_once_with(Bucket="bucket", Key="other", UploadId="upload")

    def test_racing_publisher_must_have_identical_bytes(self):
        from botocore.exceptions import ClientError

        self.client.put_object.side_effect = ClientError(
            {"Error": {"Code": "PreconditionFailed"}, "ResponseMetadata": {"HTTPStatusCode": 412}}, "PutObject"
        )
        self.client.head_object.side_effect = [self.missing, self.head]
        self.objects.put("key", self.path)
        self.client.head_object.side_effect = [self.missing, {**self.head, "ContentLength": 8}]
        with self.assertRaises(ValueError):
            self.objects.put("key", self.path)

    def test_real_sdk_validates_conditional_put_request(self):
        import boto3
        from botocore.stub import ANY, Stubber

        client = boto3.client("s3", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
        self.addCleanup(client.close)
        with Stubber(client) as stub:
            stub.add_client_error(
                "head_object",
                service_error_code="404",
                http_status_code=404,
                expected_params={"Bucket": "bucket", "Key": "key"},
            )
            stub.add_response(
                "put_object",
                {},
                {"Bucket": "bucket", "Key": "key", "Body": ANY, "IfNoneMatch": "*", "Metadata": self.head["Metadata"]},
            )
            stub.add_response("head_object", self.head, {"Bucket": "bucket", "Key": "key"})
            S3Objects(client, "bucket").put("key", self.path)
            stub.assert_no_pending_responses()


if __name__ == "__main__":
    unittest.main()
