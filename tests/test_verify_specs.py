from __future__ import annotations

import unittest

from scripts.verify_specs import (
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


if __name__ == "__main__":
    unittest.main()
