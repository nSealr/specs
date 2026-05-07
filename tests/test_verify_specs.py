from __future__ import annotations

import unittest

from scripts.verify_specs import (
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
            ["get-public-key", "ping", "sign-event-kind-1-basic"],
        )


if __name__ == "__main__":
    unittest.main()
