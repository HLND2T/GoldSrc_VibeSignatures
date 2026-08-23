from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from release_workflow_lib.errors import ReleaseWorkflowError


class GitHubApiError(ReleaseWorkflowError):
    pass


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        redirected = super().redirect_request(request, file_pointer, code, message, headers, new_url)
        if redirected is None:
            return None
        if urllib.parse.urlsplit(new_url).scheme.lower() != "https":
            raise GitHubApiError("GitHub API redirect must use HTTPS")
        if _origin(request.full_url) != _origin(new_url):
            redirected.remove_header("Authorization")
        return redirected


class GitHubReleaseApi:
    def __init__(self, *, repository: str, token: str, api_url: str = "https://api.github.com"):
        if not token:
            raise GitHubApiError("GitHub App token is required")
        self.repository = repository
        self.token = token
        self.api_url = api_url.rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        *,
        document: dict | None = None,
        raw: bytes | None = None,
        content_type: str = "application/json",
        accept: str = "application/vnd.github+json",
        allow_missing: bool = False,
        absolute: bool = False,
    ):
        if document is not None and raw is not None:
            raise GitHubApiError("GitHub request cannot contain both JSON and raw data")
        data = json.dumps(document).encode("utf-8") if document is not None else raw
        url = path if absolute else f"{self.api_url}{path}"
        if urllib.parse.urlsplit(url).scheme.lower() != "https":
            raise GitHubApiError("GitHub API requests must use HTTPS")
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": accept,
                "Content-Type": content_type,
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "GoldSrc-VibeSignatures-release",
            },
        )
        try:
            opener = urllib.request.build_opener(_SafeRedirectHandler())
            with opener.open(request, timeout=120) as response:
                payload = response.read()
        except urllib.error.HTTPError as exc:
            if allow_missing and exc.code == 404:
                return None
            body = exc.read().decode("utf-8", errors="replace")[:2000]
            raise GitHubApiError(f"GitHub API {method} {path} failed with {exc.code}: {body}") from exc
        if accept == "application/octet-stream":
            return payload
        if not payload:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            raise GitHubApiError(f"GitHub API returned invalid JSON for {method} {path}") from exc

    def get_annotated_tag(self, tag: str) -> dict | None:
        reference = self._request(
            "GET",
            f"/repos/{self.repository}/git/ref/tags/{urllib.parse.quote(tag, safe='')}",
            allow_missing=True,
        )
        if reference is None:
            return None
        object_sha = reference["object"]["sha"]
        tag_object = self._request("GET", f"/repos/{self.repository}/git/tags/{object_sha}")
        if tag_object.get("object", {}).get("type") != "commit":
            raise GitHubApiError("Release tag does not target a commit")
        return {"object_sha": object_sha, "target_sha": tag_object["object"]["sha"]}

    def create_annotated_tag(self, *, tag: str, target_sha: str, message: str) -> dict:
        existing = self.get_annotated_tag(tag)
        if existing is not None:
            if existing["target_sha"] != target_sha:
                raise GitHubApiError("Existing immutable release tag targets a different commit")
            return existing
        tag_object = self._request(
            "POST",
            f"/repos/{self.repository}/git/tags",
            document={
                "tag": tag,
                "message": message,
                "object": target_sha,
                "type": "commit",
            },
        )
        object_sha = tag_object["sha"]
        self._request(
            "POST",
            f"/repos/{self.repository}/git/refs",
            document={"ref": f"refs/tags/{tag}", "sha": object_sha},
        )
        return {"object_sha": object_sha, "target_sha": target_sha}

    def get_release(self, tag: str) -> dict | None:
        return self._request(
            "GET",
            f"/repos/{self.repository}/releases/tags/{urllib.parse.quote(tag, safe='')}",
            allow_missing=True,
        )

    def create_draft_release(self, *, tag: str, target_sha: str, name: str) -> dict:
        existing = self.get_release(tag)
        if existing is not None:
            return existing
        return self._request(
            "POST",
            f"/repos/{self.repository}/releases",
            document={
                "tag_name": tag,
                "target_commitish": target_sha,
                "name": name,
                "draft": True,
                "prerelease": False,
            },
        )

    @staticmethod
    def asset_by_name(release: dict, name: str) -> dict | None:
        matches = [asset for asset in release.get("assets", []) if asset.get("name") == name]
        if len(matches) > 1:
            raise GitHubApiError(f"Release contains duplicate asset name: {name}")
        return matches[0] if matches else None

    def upload_asset(self, *, release: dict, name: str, raw: bytes) -> dict:
        existing = self.asset_by_name(release, name)
        if existing is not None:
            return existing
        upload_url = str(release["upload_url"]).split("{", 1)[0]
        separator = "&" if "?" in upload_url else "?"
        return self._request(
            "POST",
            f"{upload_url}{separator}{urllib.parse.urlencode({'name': name})}",
            raw=raw,
            content_type="application/octet-stream",
            absolute=True,
        )

    def download_asset(self, asset: dict) -> bytes:
        return self._request(
            "GET",
            f"/repos/{self.repository}/releases/assets/{asset['id']}",
            accept="application/octet-stream",
        )

    def delete_asset(self, asset_id: int) -> None:
        self._request("DELETE", f"/repos/{self.repository}/releases/assets/{asset_id}")

    def refresh_release(self, release_id: int) -> dict:
        return self._request("GET", f"/repos/{self.repository}/releases/{release_id}")

    def publish_release(self, release_id: int) -> dict:
        return self._request("PATCH", f"/repos/{self.repository}/releases/{release_id}", document={"draft": False})
