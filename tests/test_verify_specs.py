from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.verify_specs import (
    check_smartcard_apdu_vector,
    check_review_detail_page_vector,
    check_nip46_bridge_decisions,
    check_nip46_policy_file_vector,
    check_invalid_vector,
    json_utf8_size,
    implementation_limits,
    invalid_vector_names,
    load_json,
    nip46_policy_file_vector_names,
    nip46_vector_names,
    review_detail_page_vector_names,
    review_display_frame_vector_names,
    review_screen_vector_names,
    review_transcript_vector_names,
    review_vector_names,
    smartcard_apdu_vector_names,
)


ROOT = Path(__file__).resolve().parents[1]


def vector_names_from_dir(relative: str) -> list[str]:
    return sorted(path.stem for path in (ROOT / relative).glob("*.json"))


class VerifySpecsTests(unittest.TestCase):
    def test_review_vector_names_are_discovered_from_directory(self) -> None:
        names = review_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/review"))
        self.assertIn("kind-1-basic", names)
        self.assertIn("kind-1-unicode-boundary", names)

    def test_review_screen_vector_names_are_discovered_from_directory(self) -> None:
        names = review_screen_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/review-screens"))
        self.assertIn("kind-1-basic", names)

    def test_review_display_frame_vector_names_are_discovered_from_directory(self) -> None:
        names = review_display_frame_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/review-display-frames"))
        self.assertIn("kind-1-long-content-page-1-20x3", names)
        self.assertIn("kind-1-unicode-boundary-content-4x3", names)

    def test_review_detail_page_vector_names_are_discovered_from_directory(self) -> None:
        names = review_detail_page_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/review-detail-pages"))
        self.assertIn("kind-1-long-events-many-tags-t-display-s3", names)
        self.assertIn("kind-1-tags-t-display-s3", names)
        self.assertIn("kind-1-unicode-boundary-t-display-s3", names)

    def test_review_detail_page_vectors_validate_complete_display_pages(self) -> None:
        for name in review_detail_page_vector_names():
            errors: list[str] = []

            check_review_detail_page_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_review_detail_page_vectors_reject_body_style_length_drift(self) -> None:
        vector = deepcopy(load_json("vectors/review-detail-pages/kind-1-tags-t-display-s3.json"))
        vector["name"] = "mutated-detail-style-length"
        vector["pages"][2]["body_line_styles"].pop()
        source = load_json("vectors/review/kind-1-tags.json")
        screen = load_json("vectors/review-screens/kind-1-tags.json")

        def load_mutation(path: str, errors: list[str]) -> dict:
            if path == "vectors/review-detail-pages/mutated-detail-style-length.json":
                return vector
            if path == "vectors/review/kind-1-tags.json":
                return source
            if path == "vectors/review-screens/kind-1-tags.json":
                return screen
            return load_json(path)

        errors: list[str] = []
        with patch("scripts.verify_specs.load_required_json", side_effect=load_mutation):
            check_review_detail_page_vector("mutated-detail-style-length", errors)

        self.assertIn("body_line_styles length must match lines", "\n".join(errors))

    def test_review_detail_page_vectors_reject_continuation_style_drift(self) -> None:
        vector = deepcopy(load_json("vectors/review-detail-pages/kind-1-tags-t-display-s3.json"))
        vector["name"] = "mutated-detail-continuation-style"
        vector["pages"][2]["body_line_styles"][3] = "normal"
        source = load_json("vectors/review/kind-1-tags.json")
        screen = load_json("vectors/review-screens/kind-1-tags.json")

        def load_mutation(path: str, errors: list[str]) -> dict:
            if path == "vectors/review-detail-pages/mutated-detail-continuation-style.json":
                return vector
            if path == "vectors/review/kind-1-tags.json":
                return source
            if path == "vectors/review-screens/kind-1-tags.json":
                return screen
            return load_json(path)

        errors: list[str] = []
        with patch("scripts.verify_specs.load_required_json", side_effect=load_mutation):
            check_review_detail_page_vector("mutated-detail-continuation-style", errors)

        self.assertIn("continuation lines must use value style", "\n".join(errors))

    def test_review_transcript_vector_names_are_discovered_from_directory(self) -> None:
        names = review_transcript_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/review-transcripts"))
        self.assertIn("kind-1-basic-approve", names)

    def test_nip46_vector_names_are_discovered_from_directory(self) -> None:
        names = nip46_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/nip46"))
        self.assertIn("sign-event-kind-1-basic", names)

    def test_nip46_policy_file_vectors_are_discovered_from_directory(self) -> None:
        names = nip46_policy_file_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/nip46-policy-files"))
        self.assertIn("sign-event-kind-1-approved", names)

    def test_implementation_limits_are_named_and_conservative(self) -> None:
        limits = implementation_limits()

        self.assertEqual(limits["format"], "nostrseal-implementation-limits-v0")
        self.assertEqual(limits["name"], "nostrseal-v0")
        self.assertEqual(limits["limits"]["max_request_id_length"], 128)
        self.assertLessEqual(limits["limits"]["max_decoded_request_json_bytes"], 4096)
        self.assertLessEqual(limits["limits"]["max_static_qr_decoded_json_bytes"], 4096)
        self.assertLessEqual(limits["limits"]["max_nip46_decrypted_message_json_bytes"], 4096)

    def test_valid_request_vectors_fit_v0_limit_profile(self) -> None:
        limits = implementation_limits()["limits"]
        valid_request_vectors = [
            load_json(f"vectors/review/{name}.json")["request"]
            for name in review_vector_names()
        ]

        for request in valid_request_vectors:
            with self.subTest(request_id=request["request_id"]):
                request_size = json_utf8_size(request)
                self.assertLessEqual(request_size, limits["max_decoded_request_json_bytes"])
                self.assertLessEqual(request_size, limits["max_static_qr_decoded_json_bytes"])

    def test_invalid_vectors_are_discovered_from_directory(self) -> None:
        names = invalid_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/invalid"))
        self.assertIn("request-event-template-pubkey", names)
        self.assertIn("serial-frame-oversized", names)

    def test_invalid_vectors_validate_expected_rejections(self) -> None:
        for name in invalid_vector_names():
            errors: list[str] = []

            check_invalid_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_nip46_policy_file_vectors_validate_approved_permissions(self) -> None:
        errors: list[str] = []

        check_nip46_policy_file_vector("sign-event-kind-1-approved", errors)

        self.assertEqual(errors, [])

    def test_smartcard_apdu_vectors_are_discovered_from_directory(self) -> None:
        names = smartcard_apdu_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/smartcard"))
        self.assertIn("get-public-key", names)
        self.assertIn("sign-event-id-kind-1-basic", names)
        self.assertIn("sign-event-id-wrong-length", names)
        self.assertIn("unsupported-cla", names)
        self.assertIn("unsupported-ins", names)

    def test_smartcard_apdu_vectors_validate_commands_and_status_words(self) -> None:
        for name in smartcard_apdu_vector_names():
            errors: list[str] = []

            check_smartcard_apdu_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_nip46_policy_file_schema_declares_required_contract(self) -> None:
        schema = load_json("schemas/nip46-policy-file-v0.schema.json")

        self.assertEqual(schema["title"], "NostrSeal NIP-46 Policy File v0")
        self.assertEqual(schema["required"], ["format", "approved_permissions"])

    def test_nip46_permission_policy_vectors_pin_request_decisions(self) -> None:
        policy_vectors = {
            name: load_json(f"vectors/nip46/{name}.json")
            for name in ("get-public-key", "ping", "sign-event-kind-1-basic")
        }
        self.assertEqual(policy_vectors["get-public-key"]["permission_requirement"], {"method": "get_public_key"})
        self.assertEqual(policy_vectors["ping"]["permission_requirement"], {"method": "ping"})
        self.assertEqual(
            policy_vectors["sign-event-kind-1-basic"]["permission_requirement"],
            {"method": "sign_event", "parameter": "1", "event_kind": 1},
        )
        for name, vector in policy_vectors.items():
            self.assertGreaterEqual(len(vector.get("permission_checks", [])), 2, name)

    def test_nip46_bridge_decision_vectors_are_explicit(self) -> None:
        for name in nip46_vector_names():
            vector = load_json(f"vectors/nip46/{name}.json")
            self.assertGreaterEqual(len(vector.get("bridge_decisions", [])), 1, name)

        sign_event = load_json("vectors/nip46/sign-event-kind-1-basic.json")
        self.assertEqual(
            sign_event["bridge_decisions"][0]["decision"]["type"],
            "signer_request",
        )
        self.assertEqual(
            sign_event["bridge_decisions"][1]["decision"],
            {
                "type": "permission_denied",
                "permission_requirement": {
                    "method": "sign_event",
                    "parameter": "1",
                    "event_kind": 1,
                },
                "response_message": {
                    "id": "nip46-req-1",
                    "error": "permission_denied: request requires approved permission sign_event:1",
                },
            },
        )

        connect = load_json("vectors/nip46/connect-policy-review.json")
        self.assertEqual(connect["bridge_decisions"][0]["decision"]["type"], "connect_review")
        self.assertEqual(
            connect["connect_review"]["pages"],
            [
                {
                    "title": "Connect",
                    "page_indicator": "Page 1/2",
                    "body_lines": [
                        "Remote signer",
                        "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                        "Secret: provided",
                    ],
                },
                {
                    "title": "Permissions",
                    "page_indicator": "Page 2/2",
                    "body_lines": [
                        "sign_event:1",
                        "nip44_encrypt",
                    ],
                },
            ],
        )

    def test_nip46_bridge_decision_checker_rejects_mismatches(self) -> None:
        vector = deepcopy(load_json("vectors/nip46/ping.json"))
        vector["bridge_decisions"][0]["decision"]["response_message"]["result"] = "wrong"
        errors: list[str] = []

        check_nip46_bridge_decisions(
            "vectors/nip46/ping.json",
            vector,
            vector["request_message"],
            errors,
        )

        self.assertIn("bridge_decisions[0].decision mismatch", "\n".join(errors))


if __name__ == "__main__":
    unittest.main()
