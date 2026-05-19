from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.verify_specs import (
    check_access_surface_vector,
    check_smartcard_apdu_vector,
    check_device_security_profile_vector,
    check_feature_matrix_vector,
    check_review_detail_page_vector,
    check_review_transcript_vector,
    check_seedqr_vector,
    check_session_import_review_vector,
    check_static_qr_vector,
    check_nip46_bridge_decisions,
    check_nip19_nsec_vector,
    check_nip46_connection_uri_vector,
    check_nip46_policy_file_vector,
    check_policy_decision_vector,
    check_invalid_vector,
    json_utf8_size,
    implementation_limits,
    invalid_vector_names,
    load_json,
    nip46_policy_file_vector_names,
    nip46_connection_uri_vector_names,
    nip19_nsec_vector_names,
    nip46_vector_names,
    policy_decision_vector_names,
    review_detail_page_vector_names,
    review_display_frame_vector_names,
    review_screen_vector_names,
    review_transcript_vector_names,
    seedqr_vector_names,
    review_vector_names,
    smartcard_apdu_vector_names,
    session_import_review_vector_names,
    access_surface_vector_names,
    display_safe_text,
    device_security_profile_vector_names,
    feature_matrix_vector_names,
)
import scripts.verify_specs as verify_specs


ROOT = Path(__file__).resolve().parents[1]


def vector_names_from_dir(relative: str) -> list[str]:
    return sorted(path.stem for path in (ROOT / relative).glob("*.json"))


class VerifySpecsTests(unittest.TestCase):
    def test_review_vector_names_are_discovered_from_directory(self) -> None:
        names = review_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/review"))
        self.assertIn("kind-1-control-escapes", names)
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
        self.assertIn("kind-1-control-escapes-t-display-s3", names)
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

    def test_display_safe_text_renders_json_control_escapes_visibly(self) -> None:
        self.assertEqual(
            display_safe_text("line 1\nline 2\tTabbed\rCarriage\bBackspace\fFormfeed"),
            "line 1\\nline 2\\tTabbed\\rCarriage\\bBackspace\\fFormfeed",
        )

    def test_review_transcript_vector_names_are_discovered_from_directory(self) -> None:
        names = review_transcript_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/review-transcripts"))
        self.assertIn("kind-1-basic-approve", names)
        self.assertIn("kind-1-long-events-many-tags-detail-scroll-approve", names)

    def test_review_transcript_vectors_validate_display_navigation(self) -> None:
        for name in review_transcript_vector_names():
            errors: list[str] = []

            check_review_transcript_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_static_qr_transport_vectors_validate_envelope_payloads(self) -> None:
        names = [
            path.stem
            for path in sorted((ROOT / "vectors/transports").glob("qr-envelope-*.json"))
        ]
        self.assertIn("qr-envelope-kind-1-long-events-many-tags", names)
        for name in names:
            errors: list[str] = []

            check_static_qr_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_nip46_vector_names_are_discovered_from_directory(self) -> None:
        names = nip46_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/nip46"))
        self.assertIn("sign-event-kind-1-basic", names)

    def test_nip46_policy_file_vectors_are_discovered_from_directory(self) -> None:
        names = nip46_policy_file_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/nip46-policy-files"))
        self.assertIn("sign-event-kind-1-approved", names)

    def test_nip46_connection_uri_vectors_are_discovered_from_directory(self) -> None:
        names = nip46_connection_uri_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/nip46-connection-uris"))
        self.assertIn("bunker-remote-signer-token", names)
        self.assertIn("nostrconnect-client-token", names)

    def test_seedqr_vectors_are_discovered_from_directory(self) -> None:
        names = seedqr_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/seedqr"))
        self.assertIn("seedsigner-vector-1", names)

    def test_seedqr_vectors_validate_standard_and_compact_payloads(self) -> None:
        for name in seedqr_vector_names():
            errors: list[str] = []

            check_seedqr_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_nip19_nsec_vectors_are_discovered_from_directory(self) -> None:
        names = nip19_nsec_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/nip19"))
        self.assertIn("nsec-test-key-1", names)

    def test_nip19_nsec_vectors_validate_private_key_payloads(self) -> None:
        for name in nip19_nsec_vector_names():
            errors: list[str] = []

            check_nip19_nsec_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_session_import_review_vectors_are_discovered_from_directory(self) -> None:
        names = session_import_review_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/session-import-reviews"))
        self.assertIn("seedqr-vector-1", names)
        self.assertIn("nsec-test-key-1", names)

    def test_session_import_review_vectors_validate_secret_hidden_pages(self) -> None:
        for name in session_import_review_vector_names():
            errors: list[str] = []

            check_session_import_review_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_session_import_review_vectors_reject_secret_leakage(self) -> None:
        vector = deepcopy(load_json("vectors/session-import-reviews/seedqr-vector-1.json"))
        vector["pages"][0]["lines"].append("attack")
        errors: list[str] = []

        with patch("scripts.verify_specs.load_required_json") as load_mock:
            def load_mutation(path: str, errors_arg: list[str]) -> dict:
                if path == "vectors/session-import-reviews/mutated-seed-leak.json":
                    return vector
                return load_json(path)

            load_mock.side_effect = load_mutation
            check_session_import_review_vector("mutated-seed-leak", errors)

        self.assertIn("must not expose mnemonic word 'attack'", "\n".join(errors))

    def test_implementation_limits_are_named_and_conservative(self) -> None:
        limits = implementation_limits()

        self.assertEqual(limits["format"], "nsealr-implementation-limits-v0")
        self.assertEqual(limits["name"], "nsealr-v0")
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
        self.assertIn("serial-frame-unsupported-type", names)

    def test_invalid_vectors_validate_expected_rejections(self) -> None:
        for name in invalid_vector_names():
            errors: list[str] = []

            check_invalid_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_nip46_policy_file_vectors_validate_approved_permissions(self) -> None:
        errors: list[str] = []

        check_nip46_policy_file_vector("sign-event-kind-1-approved", errors)

        self.assertEqual(errors, [])

    def test_nip46_connection_uri_vectors_validate_descriptor_boundaries(self) -> None:
        for name in nip46_connection_uri_vector_names():
            errors: list[str] = []

            check_nip46_connection_uri_vector(name, errors)

            self.assertEqual(errors, [], name)

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

        self.assertEqual(schema["title"], "nSealr NIP-46 Policy File v0")
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

    def test_identity_policy_contract_vectors_are_discovered(self) -> None:
        self.assertTrue(hasattr(verify_specs, "account_descriptor_vector_names"))
        self.assertTrue(hasattr(verify_specs, "policy_profile_vector_names"))
        self.assertTrue(hasattr(verify_specs, "grant_descriptor_vector_names"))

        self.assertEqual(
            verify_specs.account_descriptor_vector_names(),
            vector_names_from_dir("vectors/accounts"),
        )
        self.assertEqual(
            verify_specs.policy_profile_vector_names(),
            vector_names_from_dir("vectors/policies"),
        )
        self.assertEqual(
            verify_specs.grant_descriptor_vector_names(),
            vector_names_from_dir("vectors/grants"),
        )
        self.assertIn("raspberry-qr-nip06-account-0", verify_specs.account_descriptor_vector_names())
        self.assertIn("esp32-qr-nip06-account-0", verify_specs.account_descriptor_vector_names())
        self.assertIn("smartcard-slot-0", verify_specs.account_descriptor_vector_names())
        self.assertIn("custom-hardware-wallet-slot-0", verify_specs.account_descriptor_vector_names())
        self.assertIn("manual-only-qr-vault", verify_specs.policy_profile_vector_names())
        self.assertIn("manual-only-displayless-smartcard", verify_specs.policy_profile_vector_names())
        self.assertIn("esp32-usb-kind-1-session", verify_specs.grant_descriptor_vector_names())

    def test_identity_policy_contract_vectors_validate(self) -> None:
        for name in verify_specs.account_descriptor_vector_names():
            errors: list[str] = []
            verify_specs.check_account_descriptor_vector(name, errors)
            self.assertEqual(errors, [], name)

        for name in verify_specs.policy_profile_vector_names():
            errors = []
            verify_specs.check_policy_profile_vector(name, errors)
            self.assertEqual(errors, [], name)

        for name in verify_specs.grant_descriptor_vector_names():
            errors = []
            verify_specs.check_grant_descriptor_vector(name, errors)
            self.assertEqual(errors, [], name)

    def test_policy_decision_vectors_are_discovered_from_directory(self) -> None:
        names = policy_decision_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/policy-decisions"))

    def test_policy_decision_vectors_validate(self) -> None:
        for name in policy_decision_vector_names():
            errors: list[str] = []

            check_policy_decision_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_feature_matrix_vectors_are_discovered_from_directory(self) -> None:
        names = feature_matrix_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/features"))
        self.assertIn("signer-feature-matrix-v0", names)

    def test_feature_matrix_vectors_validate_solution_behavior_contracts(self) -> None:
        for name in feature_matrix_vector_names():
            errors: list[str] = []

            check_feature_matrix_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_access_surface_vectors_are_discovered_from_directory(self) -> None:
        names = access_surface_vector_names()

        self.assertEqual(names, vector_names_from_dir("vectors/access-surfaces"))
        self.assertEqual(names, ["browser-provider-local-service-esp32-usb-unavailable"])

    def test_access_surface_vectors_validate_secretless_browser_boundary(self) -> None:
        for name in access_surface_vector_names():
            errors: list[str] = []

            check_access_surface_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_access_surface_vectors_reject_secret_and_safety_drift(self) -> None:
        vector = deepcopy(load_json("vectors/access-surfaces/browser-provider-local-service-esp32-usb-unavailable.json"))
        vector["client"]["secret_key"] = "00" * 32
        vector["safety"]["stores_production_secrets"] = True
        errors: list[str] = []

        with patch("scripts.verify_specs.load_required_json") as load_mock:
            def load_mutation(path: str, errors_arg: list[str]) -> dict:
                if path == "vectors/access-surfaces/mutated-browser-secret.json":
                    return vector
                return load_json(path)

            load_mock.side_effect = load_mutation
            check_access_surface_vector("mutated-browser-secret", errors)

        joined = "\n".join(errors)
        self.assertIn("must not contain secret field client.secret_key", joined)
        self.assertIn("safety boundary mismatch", joined)

    def test_device_security_profile_vectors_are_discovered_from_directory(self) -> None:
        names = device_security_profile_vector_names()

        expected = sorted(path.stem for path in (ROOT / "vectors/devices").glob("*security-profile-*.json"))
        self.assertEqual(names, expected)
        self.assertIn("esp32-s3-security-profile-development", names)

    def test_device_security_profile_vectors_validate_hardening_boundary(self) -> None:
        for name in device_security_profile_vector_names():
            errors: list[str] = []

            check_device_security_profile_vector(name, errors)

            self.assertEqual(errors, [], name)

    def test_feature_matrix_rejects_shared_feature_contract_drift(self) -> None:
        matrix = deepcopy(load_json("vectors/features/signer-feature-matrix-v0.json"))
        matrix["solutions"]["esp32_qr_vault"]["features"]["nostr_event_review_universal"][
            "contract_id"
        ] = "esp32-special-review"
        errors: list[str] = []

        verify_specs.check_feature_matrix_shape(
            "vectors/features/mutated-contract-drift.json",
            matrix,
            errors,
        )

        self.assertIn("shared feature contract drift", "\n".join(errors))

    def test_feature_matrix_keeps_stateless_qr_vault_targets_in_parity(self) -> None:
        matrix = deepcopy(load_json("vectors/features/signer-feature-matrix-v0.json"))
        matrix["solutions"]["esp32_qr_vault"]["features"]["qr_response"]["target"] = "not_applicable"
        errors: list[str] = []

        verify_specs.check_feature_matrix_shape(
            "vectors/features/mutated-vault-parity.json",
            matrix,
            errors,
        )

        self.assertIn("stateless_qr_vault parity mismatch", "\n".join(errors))

    def test_account_descriptors_reject_embedded_secret_material(self) -> None:
        account = deepcopy(load_json("vectors/accounts/raspberry-qr-nip06-account-0.json"))
        account["recovery"]["mnemonic"] = "leader monkey parrot ring guide accident before fence cannon height naive bean"
        errors: list[str] = []

        verify_specs.check_account_descriptor_shape(
            "vectors/accounts/mutated-secret-account.json",
            account,
            errors,
        )

        self.assertIn("must not contain secret field recovery.mnemonic", "\n".join(errors))

    def test_policy_profiles_reject_automation_for_qr_vault_routes(self) -> None:
        policy = deepcopy(load_json("vectors/policies/manual-only-qr-vault.json"))
        policy["mode"] = "scoped_automation"
        policy["grants_allowed"] = True
        errors: list[str] = []

        verify_specs.check_policy_profile_shape(
            "vectors/policies/mutated-qr-automation.json",
            policy,
            errors,
        )

        self.assertIn("QR vault routes must remain manual_only with grants_allowed false", "\n".join(errors))

    def test_policy_profiles_reject_automation_for_display_less_smartcard_routes(self) -> None:
        policy = deepcopy(load_json("vectors/policies/manual-only-displayless-smartcard.json"))
        policy["mode"] = "scoped_automation"
        policy["grants_allowed"] = True
        errors: list[str] = []

        verify_specs.check_policy_profile_shape(
            "vectors/policies/mutated-smartcard-automation.json",
            policy,
            errors,
        )

        self.assertIn("display-less smartcard routes must remain manual_only", "\n".join(errors))

    def test_account_descriptors_reject_display_less_smartcard_trusted_review_claims(self) -> None:
        account = deepcopy(load_json("vectors/accounts/smartcard-slot-0.json"))
        account["signer_route"]["trusted_review"] = "device_display"
        account["signer_route"]["policy_support"] = "scoped_automation"
        account["capabilities"]["physical_review"] = True
        account["capabilities"]["persistent_grants"] = True
        errors: list[str] = []

        verify_specs.check_account_descriptor_shape(
            "vectors/accounts/mutated-smartcard-trusted-review.json",
            account,
            errors,
        )

        joined = "\n".join(errors)
        self.assertIn("smartcard routes must remain display_less", joined)
        self.assertIn("display-less smartcard routes must use manual_only policy support", joined)
        self.assertIn("display-less smartcard routes must not claim physical review or approval", joined)
        self.assertIn("display-less smartcard routes must not support persistent grants", joined)

    def test_account_descriptors_reject_policy_route_mismatch(self) -> None:
        account = deepcopy(load_json("vectors/accounts/smartcard-slot-0.json"))
        account["policy_profile_id"] = "policy-scoped-automation-daily-use"
        errors: list[str] = []

        verify_specs.check_account_descriptor_shape(
            "vectors/accounts/mutated-smartcard-policy-route.json",
            account,
            errors,
        )

        self.assertIn("policy_profile_id does not include signer route type smartcard", "\n".join(errors))

    def test_grant_descriptors_reject_wildcard_or_qr_automation(self) -> None:
        grant = deepcopy(load_json("vectors/grants/esp32-usb-kind-1-session.json"))
        grant["permission"]["method"] = "*"
        grant["route_type"] = "esp32_qr_vault"
        errors: list[str] = []

        verify_specs.check_grant_descriptor_shape(
            "vectors/grants/mutated-wildcard-qr-grant.json",
            grant,
            errors,
        )

        joined = "\n".join(errors)
        self.assertIn("grant route_type must not be a stateless QR vault", joined)
        self.assertIn("grant permission must not use wildcards", joined)

        grant = deepcopy(load_json("vectors/grants/esp32-usb-kind-1-session.json"))
        grant["permission"] = {"method": "nip44_decrypt"}
        errors = []

        verify_specs.check_grant_descriptor_shape(
            "vectors/grants/mutated-decrypt-grant.json",
            grant,
            errors,
        )

        self.assertIn("decrypt grant permissions require manual review", "\n".join(errors))

    def test_identity_policy_schemas_declare_required_contracts(self) -> None:
        account_schema = load_json("schemas/account-descriptor-v0.schema.json")
        policy_schema = load_json("schemas/policy-profile-v0.schema.json")
        grant_schema = load_json("schemas/grant-descriptor-v0.schema.json")

        self.assertEqual(account_schema["title"], "nSealr Account Descriptor v0")
        self.assertIn("signer_route", account_schema["required"])
        self.assertNotIn("secret_key", account_schema["properties"])
        self.assertEqual(policy_schema["title"], "nSealr Policy Profile v0")
        self.assertIn("grants_allowed", policy_schema["required"])
        self.assertEqual(grant_schema["title"], "nSealr Grant Descriptor v0")
        self.assertIn("expires_at", grant_schema["required"])


if __name__ == "__main__":
    unittest.main()
