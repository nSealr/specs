from __future__ import annotations

from copy import deepcopy
import unittest

from scripts.verify_specs import (
    check_nip46_bridge_decisions,
    load_json,
    nip46_vector_names,
    review_display_frame_vector_names,
    review_screen_vector_names,
    review_transcript_vector_names,
    review_vector_names,
)


class VerifySpecsTests(unittest.TestCase):
    def test_review_vector_names_are_discovered_from_directory(self) -> None:
        self.assertEqual(
            review_vector_names(),
            [
                "kind-1-basic",
                "kind-1-long-events-many-tags",
                "kind-1-tags",
                "kind-30078-empty",
            ],
        )

    def test_review_screen_vector_names_are_discovered_from_directory(self) -> None:
        self.assertEqual(review_screen_vector_names(), ["kind-1-basic", "kind-1-tags"])

    def test_review_display_frame_vector_names_are_discovered_from_directory(self) -> None:
        self.assertEqual(review_display_frame_vector_names(), ["kind-1-long-content-page-1-20x3"])

    def test_review_transcript_vector_names_are_discovered_from_directory(self) -> None:
        self.assertEqual(
            review_transcript_vector_names(),
            ["kind-1-basic-approve", "kind-1-basic-reject"],
        )

    def test_nip46_vector_names_are_discovered_from_directory(self) -> None:
        self.assertEqual(
            nip46_vector_names(),
            ["connect-policy-review", "get-public-key", "ping", "sign-event-kind-1-basic", "sign-event-user-rejected"],
        )

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
