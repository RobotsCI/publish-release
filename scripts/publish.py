#!/usr/bin/env python3
"""Publish existing bytes through the Robot GitHub OIDC ingestion protocol."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


MAX_OBJECT = 5_368_709_120
MAX_JSON = 65_536
RETRIES = 3
ORAS = "ghcr.io/oras-project/oras@sha256:a3ce6b38d4c510ea9fdc0449b942ea44fb790f157e79b5e7e30b1e7460fe5579"
OCI = re.compile(r"docker\.io/[a-z0-9][a-z0-9._-]{0,63}/[a-z0-9][a-z0-9._/-]{0,191}@sha256:[a-f0-9]{64}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


class Failure(Exception):
    """A safe diagnostic with no provider body, credential or URL."""


class UploadUncertain(Failure):
    """Reconcile the candidate and obtain new grants before another upload."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def https_url(value: str, *, origin: bool = False) -> str:
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and parsed.hostname and parsed.username is None
                 and parsed.password is None and not parsed.fragment and parsed.port in (None, 443))
        if origin:
            valid = valid and parsed.path in ("", "/") and not parsed.query
        if not valid or any(ord(c) <= 32 or ord(c) >= 127 for c in value) or "\\" in value:
            raise ValueError()
    except ValueError:
        raise Failure("invalid HTTPS endpoint") from None
    return value.rstrip("/") if origin else value


def checked_json(raw: bytes):
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise Failure("invalid JSON response or document") from None


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def retry_delay(value):
    if not isinstance(value, str) or not value.isdecimal() or not 1 <= int(value) <= 60:
        raise Failure("retry delay cannot be honored within the publisher deadline")
    return int(value)


class Publisher:
    def __init__(self, env, workspace: Path):
        self.env = env
        self.work = workspace
        self.opener = build_opener(NoRedirect())
        self.retry_after = "1"
        self.upload_retry_after = "1"
        self.api = https_url(self.required("INPUT_API_BASE_URL"), origin=True)
        self.audience = self.required("INPUT_OIDC_AUDIENCE")
        self.version = self.required("INPUT_RELEASE_VERSION")
        self.minimum = self.required("INPUT_MIN_AGENT_VERSION")
        self.arch = self.required("INPUT_TARGET_ARCHITECTURE")
        if not VERSION.fullmatch(self.version) or not VERSION.fullmatch(self.minimum):
            raise Failure("invalid release or minimum agent version")
        if self.arch not in ("amd64", "arm64"):
            raise Failure("target architecture must be arm64 or amd64")
        if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,256}", self.audience):
            raise Failure("invalid OIDC audience")
        self.tag = self.required("INPUT_OCI_ARTIFACT_REFERENCE")
        if not re.fullmatch(r"docker\.io/[a-z0-9][a-z0-9._-]{0,63}/[a-z0-9][a-z0-9._/-]{0,191}:[a-z0-9][a-z0-9._-]{0,127}", self.tag):
            raise Failure("invalid Docker Hub evidence reference")
        self.username = self.required("INPUT_DOCKERHUB_USERNAME")
        self.secret = self.required("INPUT_DOCKERHUB_TOKEN")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", self.username):
            raise Failure("invalid Docker Hub username")
        if not 1 <= len(self.secret) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in self.secret):
            raise Failure("invalid Docker Hub token")
        for name, shape in (("GITHUB_REPOSITORY_ID", r"[1-9][0-9]{0,19}"),
                            ("GITHUB_RUN_ID", r"[1-9][0-9]{0,19}"),
                            ("GITHUB_SHA", r"[a-f0-9]{40,64}")):
            if not re.fullmatch(shape, self.required(name)):
                raise Failure("invalid GitHub source identity")
        self.required("GITHUB_REPOSITORY")
        self.required("GITHUB_OUTPUT")
        self.required("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        https_url(self.required("ACTIONS_ID_TOKEN_REQUEST_URL"))

    def required(self, name):
        value = self.env.get(name, "")
        if not value:
            raise Failure("required input or GitHub Actions environment is missing")
        return value

    def prepare(self):
        checkout = Path(self.required("GITHUB_WORKSPACE")).resolve(strict=True)
        for key, filename in (("INPUT_ARTIFACT_PATH", "artifact.tar.gz"), ("INPUT_SBOM_PATH", "sbom.cdx.json")):
            try:
                source = (checkout / self.required(key)).resolve(strict=True)
                source.relative_to(checkout)
                if not source.is_file() or not 0 < source.stat().st_size <= MAX_OBJECT:
                    raise ValueError()
                shutil.copyfile(source, self.work / filename)
            except (OSError, ValueError):
                raise Failure("artifact and SBOM must be nonempty files inside the checkout within size limits") from None
        self.artifact = self.work / "artifact.tar.gz"
        self.sbom = self.work / "sbom.cdx.json"
        try:
            # Read only the first tar header; never extract customer contents.
            with tarfile.open(self.artifact, mode="r|gz") as archive:
                archive.next()
        except (tarfile.TarError, OSError, EOFError):
            raise Failure("artifact must be a tar.gz archive") from None
        self.artifact_hash, self.sbom_hash = digest(self.artifact), digest(self.sbom)
        # SBOM size is bounded before parsing; the server independently validates it.
        if self.sbom.stat().st_size > 16 * 1024 * 1024:
            raise Failure("SBOM exceeds the publisher JSON limit")
        document = checked_json(self.sbom.read_bytes())
        try:
            hashes = document["metadata"]["component"]["hashes"]
            valid = (document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.5"
                     and type(document["version"]) is int and document["version"] >= 1
                     and any(h["alg"].upper() == "SHA-256" and h["content"].lower() == self.artifact_hash for h in hashes))
        except (KeyError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise Failure("CycloneDX 1.5 SBOM must bind the exact artifact SHA-256")
        identity = f'{self.env["GITHUB_REPOSITORY_ID"]}:{self.env["GITHUB_SHA"]}:{self.artifact_hash}'
        self.key = hashlib.sha256(identity.encode()).hexdigest()
        self.final_key = hashlib.sha256(f"{self.key}:finalize".encode()).hexdigest()

    def command(self, arguments, *, input=None):
        try:
            result = subprocess.run(arguments, input=input, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, check=False, timeout=300,
                                    env={k: v for k, v in self.env.items() if k != "INPUT_DOCKERHUB_TOKEN"})
        except (OSError, subprocess.TimeoutExpired):
            raise Failure("evidence tool unavailable or timed out") from None
        if result.returncode != 0:
            raise Failure("evidence signing or registry publication failed")
        return result.stdout

    def evidence(self):
        predicate = self.work / "provenance.json"
        predicate.write_text(json.dumps({"buildDefinition": {
            "buildType": "https://robots.hold404.com/release-ingestion/v1",
            "externalParameters": {"repository": self.env["GITHUB_REPOSITORY"],
                                   "repository_id": self.env["GITHUB_REPOSITORY_ID"],
                                   "commit_sha": self.env["GITHUB_SHA"], "run_id": self.env["GITHUB_RUN_ID"]},
            "resolvedDependencies": [{"uri": "artifact:sha256", "digest": {"sha256": self.artifact_hash}}]},
            "runDetails": {"builder": {"id": "github-actions"}}}))
        for filename, subject, kind, body in (("provenance.bundle.json", self.artifact, "https://slsa.dev/provenance/v1", predicate),
                                              ("sbom.bundle.json", self.sbom, "https://cyclonedx.org/bom", self.sbom)):
            bundle = self.work / filename
            self.command(["cosign", "attest-blob", "--yes", "--new-bundle-format=true", "--bundle", str(bundle),
                          "--predicate", str(body), "--type", kind, str(subject)])
            if not bundle.is_file() or not 0 < bundle.stat().st_size <= 16 * 1024 * 1024:
                raise Failure("invalid signing bundle")
        config = self.work / "docker-config"
        config.mkdir(mode=0o700)
        self.command(["docker", "--config", str(config), "login", "docker.io", "--username", self.username,
                      "--password-stdin"], input=self.secret.encode())
        raw = self.command(["docker", "run", "--rm", "--platform", "linux/amd64", "--user", f"{os.getuid()}:{os.getgid()}",
                            "--volume", f"{config}:/docker-config:ro", "--volume", f"{self.work}:/evidence:ro",
                            "--workdir", "/evidence", ORAS, "push", "--registry-config", "/docker-config/config.json",
                            "--artifact-type", "application/vnd.robots.release-evidence.v1", "--format", "json", self.tag,
                            "artifact.tar.gz:application/gzip", "sbom.cdx.json:application/vnd.cyclonedx+json",
                            "provenance.bundle.json:application/vnd.dev.sigstore.bundle.v0.3+json",
                            "sbom.bundle.json:application/vnd.dev.sigstore.bundle.v0.3+json"])
        try:
            value = checked_json(raw)["digest"]
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise Failure("invalid registry manifest digest") from None
        return self.tag.split(":", 1)[0] + "@" + value

    def request_json(self, request, *, timeout=30):
        with self.opener.open(request, timeout=timeout) as response:
            self.retry_after = response.headers.get("Retry-After", "1")
            raw = response.read(MAX_JSON + 1)
            if len(raw) > MAX_JSON:
                raise Failure("API response exceeds size limit")
            return checked_json(raw)

    def oidc(self):
        original = self.env["ACTIONS_ID_TOKEN_REQUEST_URL"]
        parsed = urlsplit(original)
        if any(k == "audience" for k, _ in parse_qsl(parsed.query)):
            raise Failure("GitHub OIDC request URL already selects an audience")
        url = original + ("&" if parsed.query else "?") + urlencode({"audience": self.audience})
        token = self.request_json(Request(url, headers={"Authorization": "bearer " + self.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]}))
        if not isinstance(token, dict) or not isinstance(token.get("value"), str) or not token["value"] or len(token["value"]) > 32768:
            raise Failure("invalid GitHub OIDC response")
        return token["value"]

    def api_request(self, path, body, key):
        for attempt in range(RETRIES):
            try:
                # Acquire a fresh short-lived identity for every attempt.
                return self.request_json(Request(self.api + path, data=json.dumps(body).encode(), method="POST",
                                                headers={"Authorization": "Bearer " + self.oidc(), "Idempotency-Key": key,
                                                         "Content-Type": "application/json", "X-Request-ID": "github-publish-" + key}))
            except HTTPError as error:
                retryable = error.code in (429, 500, 502, 503, 504)
                delay = error.headers.get("Retry-After", "1")
                error.close()
                if not retryable:
                    raise Failure(f"publication denied (HTTP {error.code})") from None
            except (URLError, TimeoutError, OSError):
                delay = "1"
            if attempt + 1 == RETRIES:
                break
            time.sleep(retry_delay(delay))
        raise Failure("publication dependency unavailable after bounded retries")

    def candidate(self, response):
        try:
            data = response["data"]
            if (not IDENTIFIER.fullmatch(data["id"]) or data["status"] not in ("UPLOADING", "VALIDATING", "READY_TO_SIGN", "REJECTED")
                    or not OCI.fullmatch(data["oci_evidence_reference"])):
                raise ValueError()
            if (data["status"] == "UPLOADING") != ("uploads" in data):
                raise ValueError()
            if data["status"] == "UPLOADING" and (not isinstance(data["uploads"], dict)
                    or set(data["uploads"]) != {"artifact", "sbom"}):
                raise ValueError()
            return data
        except (KeyError, TypeError, ValueError):
            raise Failure("invalid candidate response") from None

    def upload(self, grant, path):
        try:
            url = https_url(grant["upload_url"])
            headers = grant["required_headers"]
            if not isinstance(headers, dict) or len(headers) > 16:
                raise ValueError()
            for key, value in headers.items():
                if (not re.fullmatch(r"[A-Za-z0-9-]{1,128}", key)
                        or key.lower() in ("authorization", "cookie", "host", "proxy-authorization", "transfer-encoding")
                        or not isinstance(value, str) or not 1 <= len(value) <= 4096 or "\r" in value or "\n" in value):
                    raise ValueError()
            headers = dict(headers)
            lengths = [v for k, v in headers.items() if k.lower() == "content-length"]
            if lengths and (len(lengths) != 1 or lengths[0] != str(path.stat().st_size)):
                raise ValueError()
            if not lengths:
                headers["Content-Length"] = str(path.stat().st_size)
        except (KeyError, TypeError, ValueError):
            raise Failure("invalid upload grant") from None
        try:
            with path.open("rb") as source:
                with self.opener.open(Request(url, data=source, headers=headers, method="PUT"), timeout=540) as response:
                    if not 200 <= response.status < 300:
                        raise UploadUncertain("upload outcome requires fresh grants")
        except HTTPError as error:
            code = error.code
            self.upload_retry_after = error.headers.get("Retry-After", "1")
            error.close()
            if code in (400, 401, 403, 408, 409, 412, 429, 500, 502, 503, 504):
                raise UploadUncertain("upload outcome requires fresh grants") from None
            raise Failure("artifact upload denied") from None
        except (URLError, TimeoutError, OSError):
            self.upload_retry_after = "1"
            raise UploadUncertain("upload outcome requires fresh grants") from None

    def publish(self):
        self.prepare()
        reference = self.evidence()
        body = {"release_kind": "application", "release_version": self.version,
                "target": {"os": "linux", "architectures": [self.arch], "min_agent_version": self.minimum, "hardware_constraint_ids": []},
                "artifact": {"digest": {"algorithm": "sha256", "value": self.artifact_hash}, "size_bytes": self.artifact.stat().st_size, "media_type": "application/gzip"},
                "sbom": {"digest": {"algorithm": "sha256", "value": self.sbom_hash}, "size_bytes": self.sbom.stat().st_size, "media_type": "application/vnd.cyclonedx+json"},
                "oci_attestations": {"oci_reference": reference}}
        for attempt in range(RETRIES):
            data = self.candidate(self.api_request("/api/v1/github/release-ingestions", body, self.key))
            if data["status"] != "UPLOADING":
                break
            try:
                self.upload(data["uploads"]["artifact"], self.artifact)
                self.upload(data["uploads"]["sbom"], self.sbom)
                break
            except UploadUncertain:
                if attempt + 1 == RETRIES:
                    raise Failure("uploads could not be reconciled within bounded retries") from None
                time.sleep(retry_delay(self.upload_retry_after))
        if data["status"] not in ("READY_TO_SIGN", "REJECTED"):
            for attempt in range(RETRIES):
                result = self.api_request(f'/api/v1/github/release-ingestions/{data["id"]}/finalize',
                                          {"registry_credentials": {"username": self.username, "token": self.secret}}, self.final_key)
                try:
                    terminal = result["data"]
                    if terminal["id"] != data["id"] or terminal["status"] not in ("VALIDATING", "READY_TO_SIGN", "REJECTED"):
                        raise ValueError()
                except (KeyError, TypeError, ValueError):
                    raise Failure("invalid finalization response") from None
                data["status"] = terminal["status"]
                if data["status"] != "VALIDATING":
                    break
                if attempt + 1 < RETRIES:
                    time.sleep(retry_delay(self.retry_after))
        if data["status"] != "READY_TO_SIGN":
            raise Failure("candidate rejected or verification remains incomplete")
        outputs = {"release-id": data["id"], "status": data["status"], "artifact-sha256": self.artifact_hash,
                   "sbom-sha256": self.sbom_hash, "oci-evidence-reference": data["oci_evidence_reference"]}
        with Path(self.env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            for key, value in outputs.items():
                output.write(f"{key}={value}\n")
        return outputs


def main():
    previous = os.umask(0o077)
    def terminate(signum, frame):
        raise KeyboardInterrupt()
    previous_term = signal.signal(signal.SIGTERM, terminate)
    try:
        with tempfile.TemporaryDirectory(prefix="robot-publish-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
            Publisher(dict(os.environ), Path(temporary)).publish()
    except Failure as error:
        print(f"Robot publication failed: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Robot publication interrupted; reconcile the original candidate before retrying.", file=sys.stderr)
        return 130
    except Exception:
        # Unexpected library errors must also not echo request/provider content.
        print("Robot publication failed; verify inputs, current repository authorization and dependency availability.", file=sys.stderr)
        return 1
    finally:
        os.umask(previous)
        signal.signal(signal.SIGTERM, previous_term)
    print("Robot release candidate verified: READY_TO_SIGN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
