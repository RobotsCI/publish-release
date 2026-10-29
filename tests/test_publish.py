"""Behavioral tests run the publisher against controlled provider boundaries."""

from contextlib import ExitStack
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from jsonschema import Draft202012Validator
import yaml

SCRIPT = Path(__file__).parents[1] / "scripts/publish.py"
SPEC = importlib.util.spec_from_file_location("publisher", SCRIPT)
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class Response(io.BytesIO):
    status = 200

    def __init__(self, value, headers=None):
        super().__init__(json.dumps(value).encode())
        self.headers = headers or {}


class Providers:
    def __init__(self):
        self.requests = []
        self.commands = []
        self.uploads = []
        self.creates = 0
        self.finalizes = 0
        self.states = ["READY_TO_SIGN"]
        self.create_state = "UPLOADING"
        self.create_mutation = lambda d: d
        self.final_mutation = lambda d: d
        self.fail_upload_once = False
        self.fail_api_once = False
        self.accepted_ref = "docker.io/customer/evidence@sha256:" + "c" * 64

    def command(self, args, **kwargs):
        self.commands.append((args, kwargs))
        if args[0] == "cosign":
            Path(args[args.index("--bundle") + 1]).write_text("{}")
        stdout = json.dumps({"digest": "sha256:" + "d" * 64}).encode()
        return subprocess.CompletedProcess(args, 0, stdout, b"")

    def open(self, request, **kwargs):
        self.requests.append(request)
        url = request.full_url
        if url.startswith("https://oidc.example/"):
            return Response({"value": "OIDC_PRIVATE_SENTINEL"})
        if request.method == "PUT":
            self.uploads.append((url, request.data.read(), dict(request.header_items())))
            if self.fail_upload_once:
                self.fail_upload_once = False
                raise URLError("PRIVATE_UPLOAD_URL_SENTINEL")
            return Response({})
        if self.fail_api_once:
            self.fail_api_once = False
            raise HTTPError(url, 503, "PRIVATE_API_BODY_SENTINEL", {"Retry-After": "2"}, io.BytesIO())
        if url.endswith("/finalize"):
            self.finalizes += 1
            status = self.states[min(self.finalizes - 1, len(self.states) - 1)]
            return Response({"data": self.final_mutation({"id": "gri_original", "status": status})}, {"Retry-After": "2"})
        self.creates += 1
        data = {"id": "gri_original", "status": self.create_state, "oci_evidence_reference": self.accepted_ref}
        if self.create_state == "UPLOADING":
            data["uploads"] = {name: {"upload_url": f"https://storage.example/{self.creates}/{name}?private=sentinel",
                                     "required_headers": {"If-None-Match": "*", "X-Amz-Meta-Sha256": "bound-value"}}
                               for name in ("artifact", "sbom")}
        return Response({"data": self.create_mutation(data)})


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.checkout = self.root / "checkout"
        self.work = self.root / "private"
        self.checkout.mkdir()
        self.work.mkdir(mode=0o700)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            content = b"customer-built-arm64-application"
            entry = tarfile.TarInfo("application")
            entry.size = len(content)
            tar.addfile(entry, io.BytesIO(content))
        self.artifact = gzip.compress(archive.getvalue(), mtime=0)
        (self.checkout / "app.tar.gz").write_bytes(self.artifact)
        self.sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                     "metadata": {"component": {"name": "customer-app", "hashes": [
                         {"alg": "SHA-256", "content": hashlib.sha256(self.artifact).hexdigest()}]}},
                     "components": [{"type": "library", "name": "actual-dependency", "version": "1.2.3"}]}
        self.save_sbom()
        self.env = {"GITHUB_WORKSPACE": str(self.checkout), "GITHUB_OUTPUT": str(self.root / "outputs"),
                    "GITHUB_REPOSITORY_ID": "123", "GITHUB_REPOSITORY": "customer/robot", "GITHUB_SHA": "a" * 40,
                    "GITHUB_RUN_ID": "456", "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.example/token?existing=1",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "OIDC_REQUEST_SENTINEL", "INPUT_API_BASE_URL": "https://api.example",
                    "INPUT_OIDC_AUDIENCE": "robot-release", "INPUT_RELEASE_VERSION": "1.2.3", "INPUT_MIN_AGENT_VERSION": "1.0.0",
                    "INPUT_TARGET_ARCHITECTURE": "arm64", "INPUT_ARTIFACT_PATH": "app.tar.gz", "INPUT_SBOM_PATH": "sbom.json",
                    "INPUT_OCI_ARTIFACT_REFERENCE": "docker.io/customer/evidence:release-1", "INPUT_DOCKERHUB_USERNAME": "customer",
                    "INPUT_DOCKERHUB_TOKEN": "REGISTRY_PRIVATE_SENTINEL"}
        self.providers = Providers()
        self.stack.enter_context(patch.object(publisher.subprocess, "run", side_effect=self.providers.command))
        self.sleep = self.stack.enter_context(patch.object(publisher.time, "sleep"))

    def save_sbom(self):
        (self.checkout / "sbom.json").write_text(json.dumps(self.sbom))

    def instance(self):
        result = publisher.Publisher(self.env, self.work)
        result.opener = self.providers
        return result

    def output(self):
        path = self.root / "outputs"
        return path.read_text() if path.exists() else ""

    def test_arm64_publication_preserves_built_bytes_and_accepts_retained_reference(self):
        sbom_bytes = (self.checkout / "sbom.json").read_bytes()
        result = self.instance().publish()
        self.assertEqual(result["status"], "READY_TO_SIGN")
        self.assertEqual(result["oci-evidence-reference"], self.providers.accepted_ref)
        self.assertEqual([row[1] for row in self.providers.uploads], [self.artifact, sbom_bytes])
        creates = [r for r in self.providers.requests if r.full_url.endswith("/release-ingestions")]
        body = json.loads(creates[0].data)
        self.assertEqual(body["target"]["architectures"], ["arm64"])
        self.assertNotIn("organization_id", body)
        self.assertNotIn("REGISTRY_PRIVATE_SENTINEL", creates[0].data.decode())
        self.assertNotIn("REGISTRY_PRIVATE_SENTINEL", self.output())
        self.assertNotIn("OIDC_PRIVATE_SENTINEL", self.output())
        self.assertNotIn("storage.example", self.output())
        for _, _, headers in self.providers.uploads:
            self.assertEqual(headers["If-none-match"], "*")
            self.assertEqual(headers["X-amz-meta-sha256"], "bound-value")
            self.assertNotIn("Authorization", headers)
        self.assertEqual(len([c for c in self.providers.commands if c[0][0] == "cosign"]), 2)
        for args, _ in self.providers.commands:
            self.assertNotIn(self.env["INPUT_DOCKERHUB_TOKEN"], " ".join(args))

    def test_produced_requests_and_consumed_responses_match_canonical_schemas(self):
        self.instance().publish()
        schemas = json.loads((SCRIPT.parents[1] / "schemas/ingestion.json").read_text())["$defs"]
        for request in self.providers.requests:
            if request.full_url.startswith("https://api.example/"):
                name = "FinalizeRequest" if request.full_url.endswith("/finalize") else "CreateRequest"
                Draft202012Validator(schemas[name]).validate(json.loads(request.data))
        replay = {"request_id": "request-fixture-01", "timestamp": "2026-10-29T12:00:00Z", "data": {
            "id": "gri_original", "status": "READY_TO_SIGN", "oci_evidence_reference": self.providers.accepted_ref}}
        validator = Draft202012Validator(schemas["CreateEnvelope"])
        validator.validate(replay)
        replay["data"]["uploads"] = {}
        self.assertFalse(validator.is_valid(replay))

    def test_amd64_is_explicit_target_metadata(self):
        self.env["INPUT_TARGET_ARCHITECTURE"] = "amd64"
        self.instance().publish()
        body = next(json.loads(r.data) for r in self.providers.requests if r.full_url.endswith("/release-ingestions"))
        self.assertEqual(body["target"]["architectures"], ["amd64"])

    def test_rejected_finalization_fails_without_success_outputs(self):
        self.providers.states = ["REJECTED"]
        with self.assertRaises(publisher.Failure):
            self.instance().publish()
        self.assertEqual(self.output(), "")

    def test_validating_retries_honor_retry_after(self):
        self.providers.states = ["VALIDATING", "READY_TO_SIGN"]
        self.instance().publish()
        self.sleep.assert_called_with(2)
        self.assertEqual(self.providers.finalizes, 2)

    def test_unresolved_verification_fails(self):
        self.providers.states = ["VALIDATING"]
        with self.assertRaises(publisher.Failure):
            self.instance().publish()
        self.assertEqual(self.providers.finalizes, 3)
        self.assertEqual(self.output(), "")

    def test_finalizer_cannot_substitute_candidate(self):
        self.providers.final_mutation = lambda d: {**d, "id": "gri_foreign"}
        with self.assertRaises(publisher.Failure):
            self.instance().publish()

    def test_existing_terminal_candidate_has_no_upload_or_finalize(self):
        self.providers.create_state = "READY_TO_SIGN"
        self.instance().publish()
        self.assertEqual(self.providers.uploads, [])
        self.assertEqual(self.providers.finalizes, 0)

    def test_existing_rejection_is_not_revived(self):
        self.providers.create_state = "REJECTED"
        with self.assertRaises(publisher.Failure):
            self.instance().publish()
        self.assertEqual(self.providers.uploads, [])

    def test_uncertain_upload_gets_new_grants_instead_of_reusing_url(self):
        self.providers.fail_upload_once = True
        self.instance().publish()
        self.assertEqual(self.providers.creates, 2)
        self.assertNotEqual(self.providers.uploads[0][0], self.providers.uploads[1][0])
        creates = [r for r in self.providers.requests if r.full_url.endswith("/release-ingestions")]
        self.assertEqual(creates[0].data, creates[1].data)
        self.assertEqual(creates[0].get_header("Idempotency-key"), creates[1].get_header("Idempotency-key"))

    def test_transient_api_failure_retries_with_same_operation(self):
        self.providers.fail_api_once = True
        self.instance().publish()
        self.sleep.assert_called_with(2)
        oidc = [r for r in self.providers.requests if r.full_url.startswith("https://oidc.example/")]
        self.assertEqual(len(oidc), 3)

    def test_malformed_candidate_status_fails(self):
        self.providers.create_mutation = lambda d: {**d, "status": "SIGNED"}
        with self.assertRaises(publisher.Failure):
            self.instance().publish()
        self.assertEqual(self.providers.uploads, [])

    def test_terminal_candidate_cannot_include_upload_grants(self):
        self.providers.create_mutation = lambda d: {**d, "status": "READY_TO_SIGN"}
        with self.assertRaises(publisher.Failure):
            self.instance().publish()

    def test_bad_sbom_digest_fails_before_provider_work(self):
        self.sbom["metadata"]["component"]["hashes"][0]["content"] = "0" * 64
        self.save_sbom()
        with self.assertRaises(publisher.Failure):
            self.instance().publish()
        self.assertEqual(self.providers.commands, [])
        self.assertEqual(self.providers.requests, [])

    def test_gzip_without_tar_is_rejected(self):
        (self.checkout / "app.tar.gz").write_bytes(gzip.compress(b"not a tar archive"))
        with self.assertRaises(publisher.Failure):
            self.instance().publish()
        self.assertEqual(self.providers.commands, [])

    def test_incomplete_grants_fail_before_upload(self):
        def missing(data):
            del data["uploads"]["sbom"]
            return data
        self.providers.create_mutation = missing
        with self.assertRaises(publisher.Failure):
            self.instance().publish()
        self.assertEqual(self.providers.uploads, [])

    def test_cli_cleans_private_files_and_reports_only_safe_failure(self):
        scratch = self.root / "runner-temp"
        scratch.mkdir()
        def fail(instance):
            (instance.work / "credential.json").write_text("REGISTRY_PRIVATE_SENTINEL")
            raise publisher.Failure("evidence signing or registry publication failed")
        stderr = io.StringIO()
        with patch.dict(publisher.os.environ, {**self.env, "RUNNER_TEMP": str(scratch)}, clear=True), \
                patch.object(publisher.Publisher, "publish", fail), patch.object(publisher.sys, "stderr", stderr):
            self.assertEqual(publisher.main(), 1)
        self.assertEqual(list(scratch.iterdir()), [])
        self.assertNotIn("PRIVATE_SENTINEL", stderr.getvalue())

    def test_interruption_cleans_private_files(self):
        scratch = self.root / "runner-temp"
        scratch.mkdir()
        def interrupted(instance):
            (instance.work / "credential.json").write_text("REGISTRY_PRIVATE_SENTINEL")
            raise KeyboardInterrupt()
        with patch.dict(publisher.os.environ, {**self.env, "RUNNER_TEMP": str(scratch)}, clear=True), \
                patch.object(publisher.Publisher, "publish", interrupted), patch.object(publisher.sys, "stderr", io.StringIO()):
            self.assertEqual(publisher.main(), 130)
        self.assertEqual(list(scratch.iterdir()), [])

    def test_request_ids_and_idempotency_keys_have_canonical_shapes(self):
        self.instance().publish()
        for request in self.providers.requests:
            if request.full_url.startswith("https://api.example/"):
                self.assertRegex(request.get_header("Idempotency-key"), r"^[a-f0-9]{64}$")
                self.assertRegex(request.get_header("X-request-id"), r"^[A-Za-z0-9._:-]{8,128}$")

    def test_oidc_url_keeps_existing_encoded_query_and_encodes_audience(self):
        self.env["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://oidc.example/token?encoded=%2F%2b&existing=1"
        self.env["INPUT_OIDC_AUDIENCE"] = "https://api.example/release"
        self.instance().publish()
        oidc = next(r for r in self.providers.requests if r.full_url.startswith("https://oidc.example/"))
        self.assertIn("encoded=%2F%2b&existing=1&audience=https%3A%2F%2Fapi.example%2Frelease", oidc.full_url)

    def test_no_synthetic_sbom_or_rewrite_for_unsupported_format(self):
        self.sbom["specVersion"] = "1.6"
        self.save_sbom()
        before = (self.checkout / "sbom.json").read_bytes()
        with self.assertRaises(publisher.Failure):
            self.instance().publish()
        self.assertEqual((self.checkout / "sbom.json").read_bytes(), before)

    def test_input_must_resolve_inside_checkout(self):
        (self.root / "outside.tar.gz").write_bytes(self.artifact)
        self.env["INPUT_ARTIFACT_PATH"] = "../outside.tar.gz"
        with self.assertRaises(publisher.Failure):
            self.instance().publish()

    def test_endpoint_rejects_credentials_query_fragment_and_http(self):
        for url in ("http://api.example", "https://user:secret@api.example", "https://api.example?secret=x",
                    "https://api.example#secret", "https://api.example/other", "https://api.example:8443"):
            with self.subTest(url=url):
                env = {**self.env, "INPUT_API_BASE_URL": url}
                with self.assertRaises(publisher.Failure):
                    publisher.Publisher(env, self.work)

    def test_upload_rejects_header_injection_and_credentials(self):
        instance = self.instance()
        path = self.checkout / "app.tar.gz"
        for headers in ({"Authorization": "Bearer private"}, {"x-test": "x\r\nprivate"}, {"Content-Length": "1"}):
            with self.subTest(headers=headers):
                with self.assertRaises(publisher.Failure):
                    instance.upload({"upload_url": "https://storage.example/upload", "required_headers": headers}, path)
        self.assertEqual(self.providers.uploads, [])

    def test_no_redirect_for_credentialed_requests(self):
        self.assertIsNone(publisher.NoRedirect().redirect_request(None, None, 302, "", {}, "https://foreign.example"))

    def test_duplicate_json_members_rejected(self):
        with self.assertRaises(publisher.Failure):
            publisher.checked_json(b'{"status":"READY_TO_SIGN","status":"REJECTED"}')

    def test_over_budget_retry_after_fails_without_spinning(self):
        self.providers.states = ["VALIDATING"]
        old = self.providers.open
        def delayed(request, **kwargs):
            response = old(request, **kwargs)
            response.headers["Retry-After"] = "3600"
            return response
        self.providers.open = delayed
        with self.assertRaises(publisher.Failure):
            self.instance().publish()
        self.sleep.assert_not_called()


class ActionMetadataTests(unittest.TestCase):
    def test_composite_inputs_outputs_and_shell(self):
        action = yaml.safe_load((SCRIPT.parents[1] / "action.yml").read_text())
        self.assertEqual(action["runs"]["using"], "composite")
        self.assertTrue(all(value["required"] for value in action["inputs"].values()))
        self.assertEqual(set(action["outputs"]), {"release-id", "status", "artifact-sha256", "sbom-sha256", "oci-evidence-reference"})
        for step in action["runs"]["steps"]:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[a-f0-9]{40}$")
            if "run" in step:
                checked = subprocess.run(["bash", "-n"], input=step["run"], text=True, capture_output=True)
                self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(set(action["runs"]["steps"][-1]["env"]),
                         {"INPUT_" + key.replace("-", "_").upper() for key in action["inputs"]})


if __name__ == "__main__":
    unittest.main()
