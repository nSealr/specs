#!/usr/bin/env python3
"""Verify nSealr M1 specs, examples, and cryptographic fixtures."""

from __future__ import annotations

import hashlib
import json
import re
import base64
import binascii
from pathlib import Path

import secp256k1


ROOT = Path(__file__).resolve().parents[1]
HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{128}$")
HEX8_RE = re.compile(r"^[0-9a-f]{16}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
QR_PREFIX = "nsealr1:"
ANIMATED_QR_PREFIX = "nsealr1a:"
SERIAL_PREFIX = "nsealr1f:"
APDU_HEX_RE = re.compile(r"^[0-9a-f]+$")
LIMIT_PROFILE = "vectors/limits/nsealr-v0.json"
DEVICE_METHODS = {"get_capabilities", "get_signing_status", "get_public_key", "sign_event"}
ROUTE_TYPES = {
    "raspberry_qr_vault",
    "esp32_qr_vault",
    "esp32_usb_nip46",
    "smartcard",
    "custom_hardware_wallet",
    "external_nip46",
}
QR_ROUTE_TYPES = {"raspberry_qr_vault", "esp32_qr_vault"}
ROUTE_REPOSITORIES = {
    "raspberry_qr_vault": "raspberry",
    "esp32_qr_vault": "esp32",
    "esp32_usb_nip46": "esp32",
    "smartcard": "smartcard",
    "custom_hardware_wallet": "hardware",
}
ROUTE_TRANSPORTS = {"qr", "usb", "smartcard", "nfc", "nip46_relay", "embedded"}
ROUTE_CUSTODY_MODES = {
    "stateless_session",
    "device_persistent",
    "card_persistent",
    "custom_hardware_persistent",
    "external_signer",
}
ROUTE_REVIEW_MODES = {"device_display", "external_review", "external_policy", "display_less"}
POLICY_SUPPORT_MODES = {"manual_only", "scoped_automation", "external"}
POLICY_MODES = {"manual_only", "scoped_automation"}
GRANT_DECISIONS = {"allow_once", "allow_until_expiry"}
POLICY_DECISIONS = {"allow", "deny", "manual_review"}
POLICY_DECISION_REASONS = {
    "decrypt_requires_manual_review",
    "forbidden_permission",
    "grant_expired",
    "grant_revoked",
    "grant_valid",
    "no_matching_grant",
    "policy_manual_only",
    "unknown_method_requires_manual_review",
}
DECRYPT_METHODS = {"nip04_decrypt", "nip44_decrypt"}
SECRET_FIELD_NAMES = {
    "secret_key",
    "private_key",
    "nsec",
    "mnemonic",
    "seed",
    "passphrase",
    "nip49_ciphertext",
}
SIGNING_STATUS_GATES = [
    "runtime_signing_feature",
    "parser_limits",
    "trusted_review_display",
    "physical_approval_controls",
    "approval_digest_binding",
    "unicode_review_rendering",
    "key_provisioning",
    "secure_boot",
    "flash_encryption",
    "debug_lock",
    "companion_signed_output_verification",
]
ESP32_S3_SCAFFOLD_MISSING_SIGNING_GATES = [
    "runtime_signing_feature",
    "trusted_review_display",
    "physical_approval_controls",
    "unicode_review_rendering",
    "key_provisioning",
    "secure_boot",
    "flash_encryption",
    "debug_lock",
    "companion_signed_output_verification",
]
ESP32_S3_SCAFFOLD_DEVELOPMENT_ACCEPTED_SIGNING_GATES = [
    "parser_limits",
    "trusted_review_display",
    "physical_approval_controls",
    "approval_digest_binding",
]
REVIEW_DETAIL_BODY_LINE_STYLES = {"meta", "normal", "value"}
FEATURE_TARGETS = {"required", "optional", "not_applicable", "forbidden", "research"}
FEATURE_CURRENT_STATUSES = {
    "implemented",
    "partial",
    "planned",
    "hardware_blocked",
    "research",
    "not_applicable",
    "forbidden",
    "disabled_until_gates_pass",
}
FEATURE_SOLUTION_IDS = {
    "raspberry_qr_vault",
    "esp32_qr_vault",
    "esp32_usb_nip46",
    "smartcard",
    "custom_hardware_wallet",
}
FEATURE_IDS = {
    "request_validation_v0",
    "nostr_event_review_universal",
    "review_detail_pages",
    "approval_digest_binding",
    "physical_approval",
    "sign_event_bip340",
    "qr_static_request",
    "qr_animated_request",
    "qr_response",
    "stateless_session_custody",
    "manual_only_policy",
    "device_display_review",
    "serial_usb_transport",
    "nip46_decrypted_bridge",
    "scoped_policy_automation",
    "persistent_secret_custody",
    "smartcard_apdu",
    "external_review_acknowledgement",
    "secure_boot_hardening",
    "response_verification",
}
STATELESS_QR_PARITY_FEATURES = {
    "request_validation_v0",
    "nostr_event_review_universal",
    "review_detail_pages",
    "approval_digest_binding",
    "physical_approval",
    "sign_event_bip340",
    "qr_static_request",
    "qr_animated_request",
    "qr_response",
    "stateless_session_custody",
    "manual_only_policy",
    "device_display_review",
    "response_verification",
}


def load_json(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def load_required_json(rel: str, errors: list[str]) -> dict | None:
    path = ROOT / rel
    if not path.exists():
        errors.append(f"{rel}: missing required file")
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def implementation_limits() -> dict:
    return load_json(LIMIT_PROFILE)


def implementation_limit_values() -> dict:
    return implementation_limits()["limits"]


def canonical_event_serialization(event: dict) -> str:
    payload = [
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def event_id(event: dict) -> str:
    return hashlib.sha256(canonical_event_serialization(event).encode("utf-8")).hexdigest()


def base64url_json(value: dict) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return encoded.rstrip("=")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def animated_qr_checksum(digest: str, index: int, total: int, chunk: str) -> str:
    frame_without_checksum = f"{ANIMATED_QR_PREFIX}{digest}:{index}/{total}:{chunk}"
    return sha256_hex(frame_without_checksum.encode("utf-8"))[:16]


def animated_qr_frames(value: dict, chunk_size: int) -> list[str]:
    decoded = compact_json(value).encode("utf-8")
    digest = sha256_hex(decoded)
    payload = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    chunks = [payload[index : index + chunk_size] for index in range(0, len(payload), chunk_size)]
    frames = []
    for index, chunk in enumerate(chunks, start=1):
        checksum = animated_qr_checksum(digest, index, len(chunks), chunk)
        frames.append(f"{ANIMATED_QR_PREFIX}{digest}:{index}/{len(chunks)}:{chunk}:{checksum}")
    return frames


def json_utf8_size(value: object) -> int:
    return len(compact_json(value).encode("utf-8"))


def utf8_size(value: str) -> int:
    return len(value.encode("utf-8"))


def serial_checksum(frame_type: str, payload: str) -> str:
    return hashlib.sha256(f"{frame_type}:{payload}".encode("utf-8")).hexdigest()[:16]


def verify_schnorr(pubkey_hex: str, msg_hex: str, sig_hex: str) -> bool:
    xonly_pubkey = secp256k1.ffi.new("secp256k1_xonly_pubkey *")
    parsed = secp256k1.lib.secp256k1_xonly_pubkey_parse(
        secp256k1.secp256k1_ctx,
        xonly_pubkey,
        bytes.fromhex(pubkey_hex),
    )
    if parsed != 1:
        return False
    verified = secp256k1.lib.secp256k1_schnorrsig_verify(
        secp256k1.secp256k1_ctx,
        bytes.fromhex(sig_hex),
        bytes.fromhex(msg_hex),
        32,
        xonly_pubkey,
    )
    return bool(verified)


def xonly_pubkey_from_secret(secret_key_hex: str) -> str | None:
    if not HEX32_RE.fullmatch(secret_key_hex):
        return None
    private_key = secp256k1.PrivateKey(bytes.fromhex(secret_key_hex), raw=True)
    out = secp256k1.ffi.new("unsigned char [32]")
    ok = secp256k1.lib.secp256k1_xonly_pubkey_serialize(
        secp256k1.secp256k1_ctx,
        out,
        private_key.pubkey.xonly_pubkey,
    )
    if ok != 1:
        return None
    return bytes(secp256k1.ffi.buffer(out, 32)).hex()


def check_implementation_limits(errors: list[str]) -> None:
    profile = load_required_json(LIMIT_PROFILE, errors)
    if profile is None:
        return
    if profile.get("format") != "nsealr-implementation-limits-v0":
        errors.append(f"{LIMIT_PROFILE}: format mismatch")
    if profile.get("name") != "nsealr-v0":
        errors.append(f"{LIMIT_PROFILE}: name mismatch")
    limits = profile.get("limits")
    if not isinstance(limits, dict):
        errors.append(f"{LIMIT_PROFILE}: limits must be an object")
        return
    required = {
        "max_request_id_length",
        "max_decoded_request_json_bytes",
        "max_static_qr_decoded_json_bytes",
        "max_animated_qr_decoded_json_bytes",
        "max_animated_qr_frame_payload_chars",
        "max_animated_qr_frame_count",
        "max_serial_frame_bytes",
        "max_nip46_decrypted_message_json_bytes",
        "max_content_utf8_bytes",
        "max_tag_count",
        "max_tag_fields_per_tag",
        "max_tag_field_utf8_bytes",
        "max_total_tag_utf8_bytes",
        "max_safe_integer",
    }
    missing = sorted(required - set(limits))
    if missing:
        errors.append(f"{LIMIT_PROFILE}: missing limits {missing}")
    for field in required & set(limits):
        if not isinstance(limits[field], int) or limits[field] <= 0:
            errors.append(f"{LIMIT_PROFILE}: {field} must be a positive integer")
    if limits.get("max_request_id_length") != 128:
        errors.append(f"{LIMIT_PROFILE}: max_request_id_length must remain 128")
    integer_policy = profile.get("integer_policy")
    if not isinstance(integer_policy, dict):
        errors.append(f"{LIMIT_PROFILE}: integer_policy must be an object")
        return
    for field in ("created_at", "kind"):
        policy = integer_policy.get(field)
        if not isinstance(policy, dict):
            errors.append(f"{LIMIT_PROFILE}: integer_policy.{field} must be an object")
            continue
        expected = {
            "type": "integer",
            "minimum": 0,
            "maximum": limits.get("max_safe_integer"),
        }
        if policy != expected:
            errors.append(f"{LIMIT_PROFILE}: integer_policy.{field} mismatch")


def check_safe_integer(path: Path, field: str, value: object, errors: list[str], limits: dict) -> None:
    if type(value) is not int:
        errors.append(f"{path}: event_template {field} must be a non-negative safe integer")
        return
    if value < 0:
        errors.append(f"{path}: event_template {field} must be a non-negative safe integer")
    if value > limits["max_safe_integer"]:
        errors.append(f"{path}: event_template {field} exceeds max_safe_integer")


def check_signed_event_safe_integer(path: Path, field: str, value: object, errors: list[str], limits: dict) -> None:
    if type(value) is not int:
        errors.append(f"{path}: signed event {field} must be a non-negative safe integer")
        return
    if value < 0:
        errors.append(f"{path}: signed event {field} must be a non-negative safe integer")
    if value > limits["max_safe_integer"]:
        errors.append(f"{path}: signed event {field} exceeds max_safe_integer")


def check_request_shape(path: Path, value: object, errors: list[str]) -> None:
    limits = implementation_limit_values()
    if not isinstance(value, dict):
        errors.append(f"{path}: request must be an object")
        return
    if json_utf8_size(value) > limits["max_decoded_request_json_bytes"]:
        errors.append(f"{path}: decoded request JSON exceeds max_decoded_request_json_bytes")

    if value.get("version") != 1:
        errors.append(f"{path}: version must be 1")
    request_id = value.get("request_id")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        errors.append(f"{path}: request_id must match the v0 request id profile")
    elif len(request_id) > limits["max_request_id_length"]:
        errors.append(f"{path}: request_id exceeds max_request_id_length")
    method = value.get("method")
    if method not in DEVICE_METHODS:
        errors.append(f"{path}: unsupported method {method!r}")
        return
    allowed_top_level = {"version", "request_id", "method"}
    if method == "sign_event":
        allowed_top_level.add("params")
    unknown_top_level = sorted(set(value) - allowed_top_level)
    if unknown_top_level:
        errors.append(f"{path}: unknown top-level fields: {unknown_top_level}")
    if method == "get_capabilities" and "params" in value:
        errors.append(f"{path}: get_capabilities must not include params in v0")
    if method == "get_signing_status" and "params" in value:
        errors.append(f"{path}: get_signing_status must not include params in v0")
    if method == "get_public_key" and "params" in value:
        errors.append(f"{path}: get_public_key must not include params in v0")
    if method == "sign_event":
        params = value.get("params")
        if not isinstance(params, dict):
            errors.append(f"{path}: sign_event requires params")
            return
        unknown_params = sorted(set(params) - {"event_template"})
        if unknown_params:
            errors.append(f"{path}: sign_event params contain unknown fields: {unknown_params}")
        template = params.get("event_template")
        if not isinstance(template, dict):
            errors.append(f"{path}: event_template must be an object")
            return
        forbidden = {"id", "pubkey", "sig"} & set(template)
        if forbidden:
            errors.append(f"{path}: event_template contains forbidden fields: {sorted(forbidden)}")
        required_fields = {"created_at", "kind", "tags", "content"}
        unknown_template_fields = sorted(set(template) - required_fields - {"id", "pubkey", "sig"})
        if unknown_template_fields:
            errors.append(f"{path}: event_template contains unknown fields: {unknown_template_fields}")
        for field in sorted(required_fields):
            if field not in template:
                errors.append(f"{path}: event_template missing {field}")
        if "created_at" in template:
            check_safe_integer(path, "created_at", template["created_at"], errors, limits)
        if "kind" in template:
            check_safe_integer(path, "kind", template["kind"], errors, limits)
        if "tags" in template:
            tags = template["tags"]
            if not isinstance(tags, list):
                errors.append(f"{path}: event_template tags must be an array")
            else:
                if len(tags) > limits["max_tag_count"]:
                    errors.append(f"{path}: event_template tags exceeds max_tag_count")
                total_tag_bytes = 0
                for tag_index, tag in enumerate(tags):
                    if not isinstance(tag, list):
                        errors.append(f"{path}: event_template tags[{tag_index}] must be an array")
                        continue
                    if len(tag) > limits["max_tag_fields_per_tag"]:
                        errors.append(f"{path}: event_template tags[{tag_index}] exceeds max_tag_fields_per_tag")
                    for field_index, item in enumerate(tag):
                        if not isinstance(item, str):
                            errors.append(f"{path}: event_template tags[{tag_index}][{field_index}] must be a string")
                            continue
                        item_bytes = utf8_size(item)
                        total_tag_bytes += item_bytes
                        if item_bytes > limits["max_tag_field_utf8_bytes"]:
                            errors.append(f"{path}: event_template tag field exceeds max_tag_field_utf8_bytes")
                if total_tag_bytes > limits["max_total_tag_utf8_bytes"]:
                    errors.append(f"{path}: event_template tags exceed max_total_tag_utf8_bytes")
        if "content" in template:
            content = template["content"]
            if not isinstance(content, str):
                errors.append(f"{path}: event_template content must be a string")
            elif utf8_size(content) > limits["max_content_utf8_bytes"]:
                errors.append(f"{path}: event_template content exceeds max_content_utf8_bytes")


def request_shape_errors(path: Path, value: dict) -> list[str]:
    errors: list[str] = []
    check_request_shape(path, value, errors)
    return errors


def check_response_shape(path: Path, value: dict, errors: list[str]) -> None:
    limits = implementation_limit_values()
    if not isinstance(value, dict):
        errors.append(f"{path}: response must be an object")
        return
    allowed_top_level = {"version", "request_id", "ok"}
    if value.get("ok") is True:
        allowed_top_level.add("result")
    elif value.get("ok") is False:
        allowed_top_level.add("error")
    unknown_top_level = sorted(set(value) - allowed_top_level)
    if unknown_top_level:
        errors.append(f"{path}: unknown top-level response fields: {unknown_top_level}")
    if value.get("version") != 1:
        errors.append(f"{path}: version must be 1")
    request_id = value.get("request_id")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        errors.append(f"{path}: request_id is invalid")
    elif len(request_id) > limits["max_request_id_length"]:
        errors.append(f"{path}: request_id exceeds max_request_id_length")
    if value.get("ok") is True:
        if "error" in value:
            errors.append(f"{path}: successful response must not include error")
        result = value.get("result")
        if not isinstance(result, dict):
            errors.append(f"{path}: successful response requires result")
            return
        result_fields = {"public_key", "capabilities", "signing_status", "event"} & set(result)
        unknown_result_fields = sorted(set(result) - {"public_key", "capabilities", "signing_status", "event"})
        if unknown_result_fields:
            errors.append(f"{path}: successful response result has unknown fields: {unknown_result_fields}")
        if len(result_fields) != 1:
            errors.append(f"{path}: successful response result must contain exactly one result field")
            return
        if "public_key" in result and (not isinstance(result["public_key"], str) or not HEX32_RE.fullmatch(result["public_key"])):
            errors.append(f"{path}: public_key must be 32-byte lowercase hex")
        if "capabilities" in result:
            capabilities = result["capabilities"]
            if not isinstance(capabilities, dict):
                errors.append(f"{path}: capabilities must be an object")
                return
            for field in ("device", "protocols", "methods", "transports"):
                if field not in capabilities:
                    errors.append(f"{path}: capabilities missing {field}")
            if "signing_enabled" in capabilities and not isinstance(capabilities["signing_enabled"], bool):
                errors.append(f"{path}: signing_enabled must be boolean")
            if "requires_physical_approval" in capabilities and not isinstance(capabilities["requires_physical_approval"], bool):
                errors.append(f"{path}: requires_physical_approval must be boolean")
            methods = capabilities.get("methods")
            if isinstance(methods, list):
                unknown_methods = sorted(set(methods) - DEVICE_METHODS)
                if unknown_methods:
                    errors.append(f"{path}: capabilities declare unknown methods: {unknown_methods}")
        if "signing_status" in result:
            signing_status = result["signing_status"]
            if not isinstance(signing_status, dict):
                errors.append(f"{path}: signing_status must be an object")
                return
            unknown_status_fields = sorted(set(signing_status) - {"signing_enabled", "missing_gates", "development_accepted_gates"})
            if unknown_status_fields:
                errors.append(f"{path}: signing_status has unknown fields: {unknown_status_fields}")
            if not isinstance(signing_status.get("signing_enabled"), bool):
                errors.append(f"{path}: signing_status.signing_enabled must be boolean")
            missing_gates = signing_status.get("missing_gates")
            if not isinstance(missing_gates, list):
                errors.append(f"{path}: signing_status.missing_gates must be an array")
            else:
                seen_missing_gates: set[str] = set()
                for gate in missing_gates:
                    if gate not in SIGNING_STATUS_GATES:
                        errors.append(f"{path}: signing_status.missing_gates contains unknown gate {gate!r}")
                    elif gate in seen_missing_gates:
                        errors.append(f"{path}: duplicate signing_status missing gate: {gate}")
                    else:
                        seen_missing_gates.add(gate)
                if signing_status.get("signing_enabled") is True and missing_gates:
                    errors.append(f"{path}: signing_status signing_enabled true requires empty missing_gates")
                if signing_status.get("signing_enabled") is False and not missing_gates:
                    errors.append(f"{path}: signing_status signing_enabled false requires at least one missing gate")
            accepted_gates = signing_status.get("development_accepted_gates")
            if not isinstance(accepted_gates, list):
                errors.append(f"{path}: signing_status.development_accepted_gates must be an array")
            else:
                seen_accepted_gates: set[str] = set()
                for gate in accepted_gates:
                    if gate not in SIGNING_STATUS_GATES:
                        errors.append(f"{path}: signing_status.development_accepted_gates contains unknown gate {gate!r}")
                    elif gate in seen_accepted_gates:
                        errors.append(f"{path}: duplicate signing_status development_accepted gate: {gate}")
                    else:
                        seen_accepted_gates.add(gate)
        if "event" in result:
            event = result["event"]
            if not isinstance(event, dict):
                errors.append(f"{path}: signed event must be an object")
                return
            unknown_event_fields = sorted(set(event) - {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"})
            if unknown_event_fields:
                errors.append(f"{path}: signed event has unknown fields: {unknown_event_fields}")
            for field in ("id", "pubkey", "created_at", "kind", "tags", "content", "sig"):
                if field not in event:
                    errors.append(f"{path}: signed event missing {field}")
            if "id" in event and (not isinstance(event["id"], str) or not HEX32_RE.fullmatch(event["id"])):
                errors.append(f"{path}: event id must be 32-byte lowercase hex")
            if "pubkey" in event and (not isinstance(event["pubkey"], str) or not HEX32_RE.fullmatch(event["pubkey"])):
                errors.append(f"{path}: pubkey must be 32-byte lowercase hex")
            if "created_at" in event:
                check_signed_event_safe_integer(path, "created_at", event["created_at"], errors, limits)
            if "kind" in event:
                check_signed_event_safe_integer(path, "kind", event["kind"], errors, limits)
            if "tags" in event:
                tags = event["tags"]
                if not isinstance(tags, list):
                    errors.append(f"{path}: signed event tags must be an array")
                else:
                    if len(tags) > limits["max_tag_count"]:
                        errors.append(f"{path}: signed event tags exceeds max_tag_count")
                    total_tag_bytes = 0
                    for tag_index, tag in enumerate(tags):
                        if not isinstance(tag, list):
                            errors.append(f"{path}: signed event tags[{tag_index}] must be an array")
                            continue
                        if len(tag) > limits["max_tag_fields_per_tag"]:
                            errors.append(f"{path}: signed event tags[{tag_index}] exceeds max_tag_fields_per_tag")
                        for field_index, item in enumerate(tag):
                            if not isinstance(item, str):
                                errors.append(f"{path}: signed event tags[{tag_index}][{field_index}] must be a string")
                                continue
                            item_bytes = utf8_size(item)
                            total_tag_bytes += item_bytes
                            if item_bytes > limits["max_tag_field_utf8_bytes"]:
                                errors.append(f"{path}: signed event tag field exceeds max_tag_field_utf8_bytes")
                    if total_tag_bytes > limits["max_total_tag_utf8_bytes"]:
                        errors.append(f"{path}: signed event tags exceed max_total_tag_utf8_bytes")
            if "content" in event:
                content = event["content"]
                if not isinstance(content, str):
                    errors.append(f"{path}: signed event content must be a string")
                elif utf8_size(content) > limits["max_content_utf8_bytes"]:
                    errors.append(f"{path}: signed event content exceeds max_content_utf8_bytes")
            if "sig" in event and (not isinstance(event["sig"], str) or not HEX64_RE.fullmatch(event["sig"])):
                errors.append(f"{path}: signature must be 64-byte lowercase hex")
    elif value.get("ok") is False:
        if "result" in value:
            errors.append(f"{path}: error response must not include result")
        error = value.get("error")
        if not isinstance(error, dict):
            errors.append(f"{path}: error response requires error object")
            return
        for field in ("code", "message", "retryable"):
            if field not in error:
                errors.append(f"{path}: error missing {field}")
        if "code" in error and not isinstance(error["code"], str):
            errors.append(f"{path}: error code must be a string")
        if "message" in error and not isinstance(error["message"], str):
            errors.append(f"{path}: error message must be a string")
        if "retryable" in error and not isinstance(error["retryable"], bool):
            errors.append(f"{path}: error retryable must be boolean")
    else:
        errors.append(f"{path}: ok must be true or false")


def expected_review(template: dict) -> dict:
    author_pubkey = load_required_json("vectors/keys/test-key-1.json", [])["public_key"]
    content = template["content"]
    tags = template["tags"]
    return {
        "kind": template["kind"],
        "created_at": template["created_at"],
        "author_pubkey": author_pubkey,
        "content": content,
        "content_utf8_bytes": len(content.encode("utf-8")),
        "tag_count": len(tags),
        "tags": tags,
    }


def review_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "review").glob("*.json"))


def check_review_vector(rel: str, errors: list[str]) -> None:
    vector = load_required_json(f"vectors/review/{rel}.json", errors)
    if vector is None:
        return
    request = vector.get("request")
    if not isinstance(request, dict):
        errors.append(f"vectors/review/{rel}.json: request must be an object")
        return
    check_request_shape(Path(f"vectors/review/{rel}.json"), request, errors)
    if request.get("method") != "sign_event":
        errors.append(f"vectors/review/{rel}.json: request method must be sign_event")
        return
    expected = expected_review(request["params"]["event_template"])
    if vector.get("name") != rel:
        errors.append(f"vectors/review/{rel}.json: name mismatch")
    if vector.get("request") != request:
        errors.append(f"vectors/review/{rel}.json: request mismatch")
    if vector.get("review") != expected:
        errors.append(f"vectors/review/{rel}.json: review mismatch")


def expected_review_pages(review: dict) -> list[dict]:
    return [
        {
            "title": "Event",
            "lines": [
                f"Kind {review['kind']}",
                f"Created {review['created_at']}",
                "Author",
                str(review["author_pubkey"]),
            ],
            "action": "next",
        },
        {
            "title": "Content",
            "lines": [str(review["content"])],
            "action": "next",
        },
        {
            "title": "Tags",
            "lines": expected_tag_page_lines(review),
            "action": "next",
        },
        {
            "title": "Decision",
            "lines": ["Approve signing only if all pages match."],
            "action": "approve_or_reject",
        },
    ]


def expected_tag_page_lines(review: dict) -> list[str]:
    tag_count = review["tag_count"]
    if tag_count == 0:
        return ["No tags"]
    lines = []
    for index, tag in enumerate(review["tags"], start=1):
        lines.append(f"Tag {index}/{tag_count}")
        if tag:
            lines.extend(str(item) for item in tag)
        else:
            lines.append("empty tag")
    return lines


def approval_digest_for_screen_review(request: dict, review: dict, pages: list[dict]) -> str:
    payload = {
        "version": request["version"],
        "method": request["method"],
        "request_id": request["request_id"],
        "event_template": request["params"]["event_template"],
        "review": review,
        "pages": pages,
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def expected_screen_review(request: dict) -> dict:
    review = expected_review(request["params"]["event_template"])
    pages = expected_review_pages(review)
    return {
        "format": "screen-pages",
        "request_id": request["request_id"],
        "approval_digest": approval_digest_for_screen_review(request, review, pages),
        "pages": pages,
    }


def review_screen_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "review-screens").glob("*.json"))


def review_display_frame_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "review-display-frames").glob("*.json"))


def review_detail_page_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "review-detail-pages").glob("*.json"))


def review_transcript_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "review-transcripts").glob("*.json"))


def nip46_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "nip46").glob("*.json"))


def nip46_policy_file_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "nip46-policy-files").glob("*.json"))


def seedqr_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "seedqr").glob("*.json"))


def smartcard_apdu_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "smartcard").glob("*.json"))


def invalid_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "invalid").glob("*.json"))


def account_descriptor_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "accounts").glob("*.json"))


def policy_profile_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "policies").glob("*.json"))


def grant_descriptor_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "grants").glob("*.json"))


def policy_decision_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "policy-decisions").glob("*.json"))


def route_selection_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "route-selections").glob("*.json"))


def feature_matrix_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "features").glob("*.json"))


def secret_field_paths(value: object, prefix: str = "") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if str(key).lower() in SECRET_FIELD_NAMES:
                paths.append(path)
            paths.extend(secret_field_paths(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            path = f"{prefix}[{index}]" if prefix else f"[{index}]"
            paths.extend(secret_field_paths(child, path))
    return paths


def check_no_secret_fields(path: str, value: object, errors: list[str]) -> None:
    for secret_path in secret_field_paths(value):
        errors.append(f"{path}: must not contain secret field {secret_path}")


def check_string_id(path: str, field: str, value: object, errors: list[str]) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value):
        errors.append(f"{path}: {field} must be a stable string id")


def check_permission_shape(path: str, permission: object, errors: list[str], *, grant_permission: bool = False) -> None:
    if not isinstance(permission, dict):
        errors.append(f"{path}: permission must be an object")
        return
    method = permission.get("method")
    if method == "*":
        errors.append(f"{path}: grant permission must not use wildcards")
    if not isinstance(method, str) or not method:
        errors.append(f"{path}: permission.method must be a non-empty string")
    if permission.get("parameter") == "*":
        errors.append(f"{path}: grant permission must not use wildcards")
    if grant_permission and method in DECRYPT_METHODS:
        errors.append(f"{path}: decrypt grant permissions require manual review")
    if method == "sign_event":
        parameter = permission.get("parameter")
        event_kind = permission.get("event_kind")
        if not isinstance(parameter, str) or not parameter.isdigit():
            errors.append(f"{path}: sign_event permission.parameter must be a decimal event kind")
        if type(event_kind) is not int or event_kind < 0:
            errors.append(f"{path}: sign_event permission.event_kind must be a non-negative integer")
        elif isinstance(parameter, str) and parameter.isdigit() and int(parameter) != event_kind:
            errors.append(f"{path}: sign_event permission parameter/event_kind mismatch")
    unknown = sorted(set(permission) - {"method", "parameter", "event_kind"})
    if unknown:
        errors.append(f"{path}: permission has unknown fields {unknown}")


def check_account_descriptor_shape(path: str, value: object, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path}: account descriptor must be an object")
        return
    check_no_secret_fields(path, value, errors)
    if value.get("format") != "nsealr-account-descriptor-v0":
        errors.append(f"{path}: format mismatch")
    check_string_id(path, "account_id", value.get("account_id"), errors)
    if not isinstance(value.get("label"), str) or not value["label"]:
        errors.append(f"{path}: label must be a non-empty string")
    if not isinstance(value.get("public_key"), str) or not HEX32_RE.fullmatch(value["public_key"]):
        errors.append(f"{path}: public_key must be 32-byte lowercase hex")

    route = value.get("signer_route")
    if not isinstance(route, dict):
        errors.append(f"{path}: signer_route must be an object")
        return
    route_type = route.get("type")
    if route_type not in ROUTE_TYPES:
        errors.append(f"{path}: signer_route.type is unknown")
    expected_repository = ROUTE_REPOSITORIES.get(route_type)
    if expected_repository is not None and route.get("repository") != expected_repository:
        errors.append(f"{path}: signer_route.repository must be {expected_repository}")
    if expected_repository is None and "repository" in route:
        errors.append(f"{path}: external signer routes must not claim a nSealr repository")
    if route.get("transport") not in ROUTE_TRANSPORTS:
        errors.append(f"{path}: signer_route.transport is unknown")
    if route.get("custody") not in ROUTE_CUSTODY_MODES:
        errors.append(f"{path}: signer_route.custody is unknown")
    if route.get("trusted_review") not in ROUTE_REVIEW_MODES:
        errors.append(f"{path}: signer_route.trusted_review is unknown")
    if route.get("policy_support") not in POLICY_SUPPORT_MODES:
        errors.append(f"{path}: signer_route.policy_support is unknown")

    capabilities = value.get("capabilities")
    if not isinstance(capabilities, dict):
        errors.append(f"{path}: capabilities must be an object")
        return
    methods = capabilities.get("methods")
    if not isinstance(methods, list) or not all(isinstance(method, str) for method in methods):
        errors.append(f"{path}: capabilities.methods must be an array of strings")
    elif unknown_methods := sorted(set(methods) - DEVICE_METHODS):
        errors.append(f"{path}: capabilities.methods contain unknown methods {unknown_methods}")
    for field in ("physical_review", "physical_approval", "persistent_grants"):
        if not isinstance(capabilities.get(field), bool):
            errors.append(f"{path}: capabilities.{field} must be boolean")

    if route_type in QR_ROUTE_TYPES:
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True).lower()
        if "tropic01" in serialized:
            errors.append(f"{path}: stateless QR vault descriptors must not reference TROPIC01")
        if route.get("transport") != "qr":
            errors.append(f"{path}: stateless QR vault routes must use qr transport")
        if route.get("custody") != "stateless_session":
            errors.append(f"{path}: stateless QR vault routes must use stateless_session custody")
        if route.get("policy_support") != "manual_only":
            errors.append(f"{path}: stateless QR vault routes must use manual_only policy support")
        if capabilities.get("persistent_grants") is not False:
            errors.append(f"{path}: stateless QR vault routes must not support persistent grants")

    recovery = value.get("recovery")
    if not isinstance(recovery, dict):
        errors.append(f"{path}: recovery must be an object")
        return
    recovery_type = recovery.get("type")
    if recovery_type == "nip06":
        if not isinstance(recovery.get("path"), str) or not recovery["path"].startswith("m/44'/1237'/"):
            errors.append(f"{path}: NIP-06 recovery path must use the Nostr derivation prefix")
        if type(recovery.get("account")) is not int or recovery["account"] < 0:
            errors.append(f"{path}: NIP-06 recovery account must be a non-negative integer")
        source_vector = recovery.get("source_vector")
        if not isinstance(source_vector, str):
            errors.append(f"{path}: NIP-06 recovery source_vector must be a string")
        elif (ROOT / source_vector).exists():
            source = load_json(source_vector)
            if source.get("public_key") != value.get("public_key"):
                errors.append(f"{path}: NIP-06 recovery source_vector public_key mismatch")
    elif recovery_type == "device_slot":
        if not isinstance(recovery.get("slot_id"), str) or not recovery["slot_id"]:
            errors.append(f"{path}: device_slot recovery requires slot_id")
        if not isinstance(recovery.get("backup_required"), bool):
            errors.append(f"{path}: device_slot recovery requires backup_required boolean")
    elif recovery_type == "external_signer":
        if not isinstance(recovery.get("external_signer_id"), str) or not recovery["external_signer_id"]:
            errors.append(f"{path}: external_signer recovery requires external_signer_id")
    else:
        errors.append(f"{path}: recovery.type is unknown")

    policy_profile_id = value.get("policy_profile_id")
    if not isinstance(policy_profile_id, str) or not policy_profile_id.startswith("policy-"):
        errors.append(f"{path}: policy_profile_id must reference a policy-* profile")
    elif not (ROOT / "vectors" / "policies" / f"{policy_profile_id.removeprefix('policy-')}.json").exists():
        errors.append(f"{path}: policy_profile_id target is missing")


def check_policy_profile_shape(path: str, value: object, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path}: policy profile must be an object")
        return
    check_no_secret_fields(path, value, errors)
    if value.get("format") != "nsealr-policy-profile-v0":
        errors.append(f"{path}: format mismatch")
    policy_id = value.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id.startswith("policy-"):
        errors.append(f"{path}: policy_id must start with policy-")
    if not isinstance(value.get("label"), str) or not value["label"]:
        errors.append(f"{path}: label must be a non-empty string")
    route_types = value.get("route_types")
    if not isinstance(route_types, list) or not route_types:
        errors.append(f"{path}: route_types must be a non-empty array")
        route_types = []
    elif unknown_routes := sorted(set(route_types) - ROUTE_TYPES):
        errors.append(f"{path}: route_types contain unknown routes {unknown_routes}")
    mode = value.get("mode")
    if mode not in POLICY_MODES:
        errors.append(f"{path}: mode is unknown")
    if not isinstance(value.get("grants_allowed"), bool):
        errors.append(f"{path}: grants_allowed must be boolean")
    manual_review_required = value.get("manual_review_required")
    if not isinstance(manual_review_required, list) or not all(isinstance(item, str) for item in manual_review_required):
        errors.append(f"{path}: manual_review_required must be an array of strings")
    forbidden_permissions = value.get("forbidden_permissions")
    if not isinstance(forbidden_permissions, list) or not all(isinstance(item, str) for item in forbidden_permissions):
        errors.append(f"{path}: forbidden_permissions must be an array of strings")
    else:
        for required_forbidden in ("wildcard", "export_secret"):
            if required_forbidden not in forbidden_permissions:
                errors.append(f"{path}: forbidden_permissions must include {required_forbidden}")
    if value.get("risk_tiers") is not None and not isinstance(value["risk_tiers"], dict):
        errors.append(f"{path}: risk_tiers must be an object")
    if set(route_types) & QR_ROUTE_TYPES and (mode != "manual_only" or value.get("grants_allowed") is not False):
        errors.append(f"{path}: QR vault routes must remain manual_only with grants_allowed false")
    if mode == "manual_only" and value.get("grants_allowed") is True:
        errors.append(f"{path}: manual_only profiles must not allow grants")
    if value.get("grants_allowed") is True:
        constraints = value.get("grant_constraints")
        if not isinstance(constraints, dict):
            errors.append(f"{path}: grant_constraints are required when grants_allowed is true")
        else:
            for field in (
                "expiry_required",
                "rate_limit_required",
                "revocation_required",
                "audit_log_required",
                "device_confirmation_required",
            ):
                if constraints.get(field) is not True:
                    errors.append(f"{path}: grant_constraints.{field} must be true")


def check_grant_descriptor_shape(path: str, value: object, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path}: grant descriptor must be an object")
        return
    check_no_secret_fields(path, value, errors)
    if value.get("format") != "nsealr-grant-descriptor-v0":
        errors.append(f"{path}: format mismatch")
    check_string_id(path, "grant_id", value.get("grant_id"), errors)
    check_string_id(path, "account_id", value.get("account_id"), errors)
    route_type = value.get("route_type")
    if route_type not in ROUTE_TYPES:
        errors.append(f"{path}: route_type is unknown")
    if route_type in QR_ROUTE_TYPES:
        errors.append(f"{path}: grant route_type must not be a stateless QR vault")
    client = value.get("client")
    if not isinstance(client, dict):
        errors.append(f"{path}: client must be an object")
    elif not isinstance(client.get("pubkey"), str) or not HEX32_RE.fullmatch(client["pubkey"]):
        errors.append(f"{path}: client.pubkey must be 32-byte lowercase hex")
    check_permission_shape(path, value.get("permission"), errors, grant_permission=True)
    decision = value.get("decision")
    if decision not in GRANT_DECISIONS:
        errors.append(f"{path}: decision is unknown")
    if decision == "allow_until_expiry" and (type(value.get("expires_at")) is not int or value["expires_at"] <= 0):
        errors.append(f"{path}: allow_until_expiry requires positive expires_at")
    rate_limit = value.get("rate_limit")
    if not isinstance(rate_limit, dict):
        errors.append(f"{path}: rate_limit must be an object")
    else:
        for field in ("max_uses", "window_seconds"):
            if type(rate_limit.get(field)) is not int or rate_limit[field] <= 0:
                errors.append(f"{path}: rate_limit.{field} must be a positive integer")
    if value.get("requires_device_policy_confirmation") is not True:
        errors.append(f"{path}: requires_device_policy_confirmation must be true")
    if value.get("revocable") is not True:
        errors.append(f"{path}: revocable must be true")
    if value.get("audit_event_format") != "nsealr-grant-audit-event-v0":
        errors.append(f"{path}: audit_event_format mismatch")


def check_account_descriptor_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/accounts/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    check_account_descriptor_shape(vector_path, vector, errors)


def check_policy_profile_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/policies/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    check_policy_profile_shape(vector_path, vector, errors)
    policy_id = vector.get("policy_id")
    if isinstance(policy_id, str) and policy_id != f"policy-{rel}":
        errors.append(f"{vector_path}: policy_id/file name mismatch")


def check_grant_descriptor_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/grants/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    check_grant_descriptor_shape(vector_path, vector, errors)
    account_id = vector.get("account_id")
    route_type = vector.get("route_type")
    matching_accounts = []
    for name in account_descriptor_vector_names():
        account = load_json(f"vectors/accounts/{name}.json")
        if account.get("account_id") == account_id:
            matching_accounts.append(account)
    if not matching_accounts:
        errors.append(f"{vector_path}: account_id target is missing")
    elif matching_accounts[0].get("signer_route", {}).get("type") != route_type:
        errors.append(f"{vector_path}: account route_type mismatch")


def policy_permission_key(permission: dict) -> str:
    if permission.get("method") == "sign_event":
        return f"sign_event:{permission.get('event_kind')}"
    return str(permission.get("method"))


def permissions_match(grant_permission: dict, request_permission: dict) -> bool:
    if grant_permission.get("method") != request_permission.get("method"):
        return False
    if grant_permission.get("method") == "sign_event":
        return (
            grant_permission.get("parameter") == request_permission.get("parameter")
            and grant_permission.get("event_kind") == request_permission.get("event_kind")
        )
    return "parameter" not in grant_permission and "event_kind" not in grant_permission


def policy_audit_event(request: dict, decision: str, reason: str, grant_id: str | None = None) -> dict:
    event = {
        "format": "nsealr-grant-audit-event-v0",
        "occurred_at": request["now"],
        "account_id": request["account_id"],
        "route_type": request["route_type"],
        "client_pubkey": request["client_pubkey"],
        "permission": request["permission"],
        "decision": decision,
        "reason": reason,
    }
    if grant_id is not None:
        event["grant_id"] = grant_id
    return event


def policy_decision(decision: str, reason: str, request: dict, grant_id: str | None = None) -> dict:
    result = {
        "format": "nsealr-policy-decision-v0",
        "decision": decision,
        "reason": reason,
        "audit_event": policy_audit_event(request, decision, reason, grant_id),
    }
    if grant_id is not None:
        result["grant_id"] = grant_id
    return result


def expected_policy_decision(vector_path: str, vector: dict, errors: list[str]) -> dict | None:
    request = vector.get("request")
    if not isinstance(request, dict):
        errors.append(f"{vector_path}: request must be an object")
        return None
    profile_id = vector.get("policy_profile_id")
    if not isinstance(profile_id, str) or not profile_id.startswith("policy-"):
        errors.append(f"{vector_path}: policy_profile_id must reference a policy-* profile")
        return None
    policy_path = f"vectors/policies/{profile_id.removeprefix('policy-')}.json"
    policy = load_required_json(policy_path, errors)
    if policy is None:
        return None

    permission = request.get("permission")
    if not isinstance(permission, dict):
        errors.append(f"{vector_path}: request.permission must be an object")
        return None
    method = permission.get("method")
    forbidden_permissions = policy.get("forbidden_permissions", [])
    if method in forbidden_permissions or method == "export_secret":
        return policy_decision("deny", "forbidden_permission", request)
    if method in DECRYPT_METHODS:
        return policy_decision("manual_review", "decrypt_requires_manual_review", request)
    if method == "unknown_method":
        return policy_decision("manual_review", "unknown_method_requires_manual_review", request)
    if policy.get("grants_allowed") is not True:
        return policy_decision("manual_review", "policy_manual_only", request)

    revoked = set(request.get("revoked_grant_ids", []))
    for grant_id in request.get("grant_ids", []):
        if not isinstance(grant_id, str):
            errors.append(f"{vector_path}: request.grant_ids must contain strings")
            continue
        grant = load_required_json(f"vectors/grants/{grant_id.removeprefix('grant-')}.json", errors)
        if grant is None:
            continue
        if grant.get("account_id") != request.get("account_id"):
            continue
        if grant.get("route_type") != request.get("route_type"):
            continue
        if grant.get("client", {}).get("pubkey") != request.get("client_pubkey"):
            continue
        grant_permission = grant.get("permission")
        if not isinstance(grant_permission, dict) or not permissions_match(grant_permission, permission):
            continue
        if grant_id in revoked:
            return policy_decision("deny", "grant_revoked", request, grant_id)
        if type(request.get("now")) is int and type(grant.get("expires_at")) is int and request["now"] >= grant["expires_at"]:
            return policy_decision("deny", "grant_expired", request, grant_id)
        return policy_decision("allow", "grant_valid", request, grant_id)
    return policy_decision("manual_review", "no_matching_grant", request)


def check_policy_decision_request_shape(path: str, request: object, errors: list[str]) -> None:
    if not isinstance(request, dict):
        errors.append(f"{path}: request must be an object")
        return
    check_string_id(path, "request.account_id", request.get("account_id"), errors)
    if request.get("route_type") not in ROUTE_TYPES:
        errors.append(f"{path}: request.route_type is unknown")
    if not isinstance(request.get("client_pubkey"), str) or not HEX32_RE.fullmatch(request["client_pubkey"]):
        errors.append(f"{path}: request.client_pubkey must be 32-byte lowercase hex")
    check_permission_shape(path, request.get("permission"), errors)
    if type(request.get("now")) is not int or request["now"] <= 0:
        errors.append(f"{path}: request.now must be a positive integer")
    grant_ids = request.get("grant_ids")
    if not isinstance(grant_ids, list) or not all(isinstance(item, str) for item in grant_ids):
        errors.append(f"{path}: request.grant_ids must be an array of strings")
    revoked_grant_ids = request.get("revoked_grant_ids")
    if not isinstance(revoked_grant_ids, list) or not all(isinstance(item, str) for item in revoked_grant_ids):
        errors.append(f"{path}: request.revoked_grant_ids must be an array of strings")


def check_policy_decision_shape(path: str, decision: object, errors: list[str]) -> None:
    if not isinstance(decision, dict):
        errors.append(f"{path}: decision must be an object")
        return
    if decision.get("format") != "nsealr-policy-decision-v0":
        errors.append(f"{path}: decision format mismatch")
    if decision.get("decision") not in POLICY_DECISIONS:
        errors.append(f"{path}: decision is unknown")
    if decision.get("reason") not in POLICY_DECISION_REASONS:
        errors.append(f"{path}: reason is unknown")
    audit = decision.get("audit_event")
    if not isinstance(audit, dict):
        errors.append(f"{path}: audit_event must be an object")
        return
    if audit.get("format") != "nsealr-grant-audit-event-v0":
        errors.append(f"{path}: audit_event format mismatch")
    if audit.get("decision") != decision.get("decision") or audit.get("reason") != decision.get("reason"):
        errors.append(f"{path}: audit_event decision/reason mismatch")


def check_policy_decision_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/policy-decisions/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    if not isinstance(vector, dict):
        errors.append(f"{vector_path}: policy decision vector must be an object")
        return
    check_no_secret_fields(vector_path, vector, errors)
    if vector.get("name") != rel:
        errors.append(f"{vector_path}: name mismatch")
    if vector.get("format") != "nsealr-policy-decision-vector-v0":
        errors.append(f"{vector_path}: format mismatch")
    check_policy_decision_request_shape(vector_path, vector.get("request"), errors)
    check_policy_decision_shape(vector_path, vector.get("decision"), errors)
    expected = expected_policy_decision(vector_path, vector, errors)
    if expected is not None and vector.get("decision") != expected:
        errors.append(f"{vector_path}: decision mismatch")


def route_selection_from_account(account: dict) -> dict:
    route = account["signer_route"]
    capabilities = account["capabilities"]
    selection = {
        "format": "nsealr-route-selection-v0",
        "account_id": account["account_id"],
        "public_key": account["public_key"],
        "route_type": route["type"],
        "transport": route["transport"],
        "custody": route["custody"],
        "trusted_review": route["trusted_review"],
        "policy_support": route["policy_support"],
        "policy_profile_id": account["policy_profile_id"],
        "physical_review": capabilities["physical_review"],
        "physical_approval": capabilities["physical_approval"],
        "persistent_grants": capabilities["persistent_grants"],
        "contains_secret_material": False,
    }
    if "repository" in route:
        selection["repository"] = route["repository"]
    return selection


def check_route_selection_request_shape(path: str, request: object, errors: list[str]) -> None:
    if not isinstance(request, dict):
        errors.append(f"{path}: request must be an object")
        return
    unknown = sorted(set(request) - {"account_id", "method", "route_type"})
    if unknown:
        errors.append(f"{path}: request has unknown fields {unknown}")
    check_string_id(path, "request.account_id", request.get("account_id"), errors)
    if not isinstance(request.get("method"), str) or not request["method"]:
        errors.append(f"{path}: request.method must be a non-empty string")
    if "route_type" in request and request.get("route_type") not in ROUTE_TYPES:
        errors.append(f"{path}: request.route_type is unknown")


def check_route_selection_shape(path: str, selection: object, errors: list[str]) -> None:
    if not isinstance(selection, dict):
        errors.append(f"{path}: selection must be an object")
        return
    expected_fields = {
        "format",
        "account_id",
        "public_key",
        "route_type",
        "repository",
        "transport",
        "custody",
        "trusted_review",
        "policy_support",
        "policy_profile_id",
        "physical_review",
        "physical_approval",
        "persistent_grants",
        "contains_secret_material",
    }
    unknown = sorted(set(selection) - expected_fields)
    if unknown:
        errors.append(f"{path}: selection has unknown fields {unknown}")
    if selection.get("format") != "nsealr-route-selection-v0":
        errors.append(f"{path}: selection format mismatch")
    check_string_id(path, "selection.account_id", selection.get("account_id"), errors)
    if not isinstance(selection.get("public_key"), str) or not HEX32_RE.fullmatch(selection["public_key"]):
        errors.append(f"{path}: selection.public_key must be 32-byte lowercase hex")
    if selection.get("route_type") not in ROUTE_TYPES:
        errors.append(f"{path}: selection.route_type is unknown")
    expected_repository = ROUTE_REPOSITORIES.get(selection.get("route_type"))
    if expected_repository is not None and selection.get("repository") != expected_repository:
        errors.append(f"{path}: selection.repository must be {expected_repository}")
    if expected_repository is None and "repository" in selection:
        errors.append(f"{path}: external signer selections must not claim a nSealr repository")
    if selection.get("transport") not in ROUTE_TRANSPORTS:
        errors.append(f"{path}: selection.transport is unknown")
    if selection.get("custody") not in ROUTE_CUSTODY_MODES:
        errors.append(f"{path}: selection.custody is unknown")
    if selection.get("trusted_review") not in ROUTE_REVIEW_MODES:
        errors.append(f"{path}: selection.trusted_review is unknown")
    if selection.get("policy_support") not in POLICY_SUPPORT_MODES:
        errors.append(f"{path}: selection.policy_support is unknown")
    for field in ("physical_review", "physical_approval", "persistent_grants"):
        if not isinstance(selection.get(field), bool):
            errors.append(f"{path}: selection.{field} must be boolean")
    if selection.get("contains_secret_material") is not False:
        errors.append(f"{path}: selection.contains_secret_material must be false")


def expected_route_selection(vector_path: str, vector: dict, errors: list[str]) -> dict | None:
    request = vector.get("request")
    if not isinstance(request, dict):
        return None
    account_id = request.get("account_id")
    matches = []
    for name in account_descriptor_vector_names():
        account = load_json(f"vectors/accounts/{name}.json")
        if account.get("account_id") == account_id:
            matches.append(account)
    if not matches:
        errors.append(f"{vector_path}: request.account_id target is missing")
        return None
    if len(matches) > 1:
        errors.append(f"{vector_path}: request.account_id is ambiguous")
        return None
    account = matches[0]
    route = account.get("signer_route", {})
    capabilities = account.get("capabilities", {})
    if request.get("route_type") is not None and request.get("route_type") != route.get("type"):
        errors.append(f"{vector_path}: request.route_type does not match account route")
        return None
    if request.get("method") not in capabilities.get("methods", []):
        errors.append(f"{vector_path}: request.method is not supported by account")
        return None
    return route_selection_from_account(account)


def check_route_selection_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/route-selections/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    if not isinstance(vector, dict):
        errors.append(f"{vector_path}: route selection vector must be an object")
        return
    check_no_secret_fields(vector_path, vector, errors)
    if vector.get("name") != rel:
        errors.append(f"{vector_path}: name mismatch")
    if vector.get("format") != "nsealr-route-selection-vector-v0":
        errors.append(f"{vector_path}: format mismatch")
    check_route_selection_request_shape(vector_path, vector.get("request"), errors)
    check_route_selection_shape(vector_path, vector.get("selection"), errors)
    expected = expected_route_selection(vector_path, vector, errors)
    if expected is not None and vector.get("selection") != expected:
        errors.append(f"{vector_path}: selection mismatch")


def check_review_screen_vector(rel: str, errors: list[str]) -> None:
    vector = load_required_json(f"vectors/review-screens/{rel}.json", errors)
    if vector is None:
        return
    request = vector.get("request")
    if not isinstance(request, dict):
        errors.append(f"vectors/review-screens/{rel}.json: request must be an object")
        return
    check_request_shape(Path(f"vectors/review-screens/{rel}.json"), request, errors)
    if request.get("method") != "sign_event":
        errors.append(f"vectors/review-screens/{rel}.json: request method must be sign_event")
        return
    expected_review_value = expected_review(request["params"]["event_template"])
    expected_screen = expected_screen_review(request)
    if vector.get("name") != rel:
        errors.append(f"vectors/review-screens/{rel}.json: name mismatch")
    if vector.get("review") != expected_review_value:
        errors.append(f"vectors/review-screens/{rel}.json: review mismatch")
    if vector.get("screen_review") != expected_screen:
        errors.append(f"vectors/review-screens/{rel}.json: screen_review mismatch")


def frame_for_page(page: dict, page_index: int, total_pages: int) -> dict:
    action_hint = "Next" if page["action"] == "next" else "Approve / Reject"
    return {
        "title": page["title"],
        "page_indicator": f"Page {page_index + 1}/{total_pages}",
        "body_lines": page["lines"],
        "action_hint": action_hint,
    }


def truncate_for_display(text: str, max_chars: int, *, force_ellipsis: bool = False) -> str:
    if len(text) <= max_chars and not force_ellipsis:
        return text
    if max_chars <= 3:
        return "." * max_chars
    return f"{text[: max_chars - 3]}..."


def wrap_display_line(text: str, max_line_chars: int) -> list[str]:
    if text == "":
        return [""]
    wrapped = []
    position = 0
    while position < len(text):
        remaining = len(text) - position
        if remaining <= max_line_chars:
            wrapped.append(text[position:])
            break
        cut = max_line_chars
        space = text.rfind(" ", position, position + max_line_chars)
        if space >= position:
            cut = space - position
            if cut == 0:
                cut = max_line_chars
        wrapped.append(text[position : position + cut])
        position += cut
        while position < len(text) and text[position] == " ":
            position += 1
    return wrapped


def bounded_display_body_lines(lines: list[str], limits: dict) -> list[str]:
    wrapped = []
    for line in lines:
        wrapped.extend(wrap_display_line(str(line), limits["max_line_chars"]))
    if len(wrapped) > limits["max_body_lines"]:
        wrapped = wrapped[: limits["max_body_lines"]]
        wrapped[-1] = truncate_for_display(
            wrapped[-1],
            limits["max_line_chars"],
            force_ellipsis=True,
        )
    return [truncate_for_display(line, limits["max_line_chars"]) for line in wrapped]


def display_frame_for_page(page: dict, page_index: int, total_pages: int, limits: dict) -> dict:
    action_hint = "Next" if page["action"] == "next" else "Approve / Reject"
    return {
        "title": truncate_for_display(str(page["title"]), limits["max_title_chars"]),
        "page_indicator": f"Page {page_index + 1}/{total_pages}",
        "body_lines": bounded_display_body_lines(page["lines"], limits),
        "action_hint": action_hint,
    }


def check_display_limits(path: str, limits: object, errors: list[str]) -> dict | None:
    if not isinstance(limits, dict):
        errors.append(f"{path}: limits must be an object")
        return None
    required = ("max_title_chars", "max_body_lines", "max_line_chars")
    if any(not isinstance(limits.get(field), int) or limits[field] <= 0 for field in required):
        errors.append(f"{path}: limits must contain positive integer display bounds")
        return None
    return {field: limits[field] for field in required}


def check_review_display_frame_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/review-display-frames/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    if vector.get("name") != rel:
        errors.append(f"{vector_path}: name mismatch")
    if vector.get("format") != "review-display-frame-v0":
        errors.append(f"{vector_path}: format mismatch")

    source_name = vector.get("source_review_vector")
    if not isinstance(source_name, str):
        errors.append(f"{vector_path}: source_review_vector must be a string")
        return
    source = load_required_json(f"vectors/review/{source_name}.json", errors)
    if source is None:
        return
    review = source.get("review")
    if not isinstance(review, dict):
        errors.append(f"{vector_path}: source review must be an object")
        return
    pages = expected_review_pages(review)

    page_index = vector.get("page_index")
    if not isinstance(page_index, int) or page_index < 0 or page_index >= len(pages):
        errors.append(f"{vector_path}: page_index out of range")
        return
    limits = check_display_limits(vector_path, vector.get("limits"), errors)
    if limits is None:
        return
    expected = display_frame_for_page(pages[page_index], page_index, len(pages), limits)
    if vector.get("frame") != expected:
        errors.append(f"{vector_path}: frame mismatch")


DISPLAY_SAFE_ASCII = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " !\"#$%&'()*+,-./:;<=>?@[\\]_{|}~"
)


def display_safe_text(text: str) -> str:
    out = []
    for char in text:
        codepoint = ord(char)
        if char == "\n":
            out.append("\\n")
        elif char == "\t":
            out.append("\\t")
        elif char == "\r":
            out.append("\\r")
        elif char == "\b":
            out.append("\\b")
        elif char == "\f":
            out.append("\\f")
        elif codepoint <= 0x7f and char in DISPLAY_SAFE_ASCII:
            out.append(char)
        else:
            out.append(f"U+{codepoint:04X}")
    return "".join(out)


def split_exact_display_lines(text: str, width: int) -> list[str]:
    if text == "":
        return [""]
    return [text[index:index + width] for index in range(0, len(text), width)]


def append_detail_value_lines(lines: list[str], styles: list[str], value: str, width: int) -> None:
    for line in split_exact_display_lines(value, width):
        lines.append(line)
        styles.append("value")


def append_detail_tag_item_lines(lines: list[str], styles: list[str], value: str, width: int) -> None:
    if value == "":
        return
    safe_value = display_safe_text(value)
    continuation_indent = "  "
    continuation_width = width - len(continuation_indent) if width > len(continuation_indent) else width
    position = 0
    first_line = True
    while position < len(safe_value):
        line_width = width if first_line else continuation_width
        line = safe_value[position:position + line_width]
        if not first_line and width > len(continuation_indent):
            line = continuation_indent + line
        lines.append(line)
        styles.append("value")
        position += line_width
        first_line = False


def detail_event_lines(review: dict, limits: dict) -> tuple[list[str], list[str]]:
    lines = [
        f"Kind {review['kind']}",
        f"Created {review['created_at']}",
        "Author",
    ]
    styles = ["meta", "meta", "meta"]
    append_detail_tag_item_lines(lines, styles, str(review["author_pubkey"]), limits["max_compact_line_chars"])
    return lines, styles


def detail_content_lines(review: dict, limits: dict) -> tuple[list[str], list[str]]:
    content = str(review["content"])
    if content == "":
        return ["empty content"], ["meta"]
    safe_content = display_safe_text(content)
    if len(safe_content) <= limits["max_compact_line_chars"]:
        return [safe_content], ["normal"]
    lines = [f"bytes: {utf8_size(content)}"]
    styles = ["meta"]
    append_detail_value_lines(lines, styles, safe_content, limits["max_compact_line_chars"])
    return lines, styles


def detail_tag_lines(review: dict, limits: dict) -> tuple[list[str], list[str]]:
    tags = review["tags"]
    if not tags:
        return ["No tags"], ["normal"]
    lines: list[str] = []
    styles: list[str] = []
    for tag_index, tag in enumerate(tags, start=1):
        lines.append(f"Tag {tag_index}/{len(tags)}")
        styles.append("meta")
        if tag:
            for item in tag:
                append_detail_tag_item_lines(lines, styles, str(item), limits["max_compact_line_chars"])
        else:
            lines.append("empty tag")
            styles.append("value")
    return lines, styles


def detail_page_indicator(
    page_index: int,
    page_count: int,
    first_line: int,
    last_line: int,
    line_count: int,
) -> str:
    base = f"Page {page_index}/{page_count}"
    if line_count == 0 or (first_line == 1 and last_line >= line_count):
        return base
    return f"{base} Lines {first_line}-{last_line}/{line_count}"


def append_detail_pages(
    pages: list[dict],
    title: str,
    lines: list[str],
    styles: list[str],
    limits: dict,
    logical_page_index: int,
    logical_page_count: int,
) -> None:
    lines_per_screen = limits["max_compact_body_lines"] if styles else limits["max_body_lines"]
    total = len(lines) if lines else 1
    position = 0
    while position < total:
        first_position = position
        body_lines: list[str] = []
        body_styles: list[str] = []
        for _ in range(lines_per_screen):
            if position >= len(lines):
                break
            body_lines.append(lines[position])
            body_styles.append(styles[position] if position < len(styles) else "normal")
            position += 1
        if not body_lines:
            body_lines = [""]
            body_styles = ["normal"]
            position = total
        pages.append(
            {
                "title": title,
                "lines": body_lines,
                "action": "next",
                "page_indicator": detail_page_indicator(
                    logical_page_index,
                    logical_page_count,
                    first_position + 1,
                    position,
                    total,
                ),
                "body_line_styles": body_styles,
                "logical_page_id": title,
            }
        )
        if position >= total:
            break


def expected_review_detail_pages(review: dict, limits: dict) -> list[dict]:
    pages: list[dict] = []
    append_detail_pages(pages, "Event", *detail_event_lines(review, limits), limits, 1, 4)
    append_detail_pages(pages, "Content", *detail_content_lines(review, limits), limits, 2, 4)
    append_detail_pages(pages, "Tags", *detail_tag_lines(review, limits), limits, 3, 4)
    pages.append(
        {
            "title": "Decision",
            "lines": ["Approve signing only if all pages match."],
            "action": "approve_or_reject",
            "page_indicator": "Page 4/4",
            "body_line_styles": [],
            "logical_page_id": "Decision",
        }
    )
    return pages


def check_review_detail_page_contract(vector_path: str, pages: object, errors: list[str]) -> None:
    if not isinstance(pages, list):
        errors.append(f"{vector_path}: pages must be an array")
        return
    for page_index, page in enumerate(pages):
        if not isinstance(page, dict):
            errors.append(f"{vector_path}: pages[{page_index}] must be an object")
            continue
        lines = page.get("lines")
        if not isinstance(lines, list) or not all(isinstance(line, str) for line in lines):
            errors.append(f"{vector_path}: pages[{page_index}].lines must be an array of strings")
            continue
        styles = page.get("body_line_styles")
        if styles is None:
            errors.append(f"{vector_path}: pages[{page_index}].body_line_styles is required")
            continue
        if not isinstance(styles, list) or not all(isinstance(style, str) for style in styles):
            errors.append(f"{vector_path}: pages[{page_index}].body_line_styles must be an array of strings")
            continue
        if styles and len(styles) != len(lines):
            errors.append(f"{vector_path}: pages[{page_index}].body_line_styles length must match lines")
        unknown_styles = sorted({style for style in styles if style not in REVIEW_DETAIL_BODY_LINE_STYLES})
        if unknown_styles:
            errors.append(f"{vector_path}: pages[{page_index}].body_line_styles contain unknown styles {unknown_styles}")
        for line_index, (line, style) in enumerate(zip(lines, styles)):
            if line.startswith("  ") and style != "value":
                errors.append(
                    f"{vector_path}: pages[{page_index}].lines[{line_index}] continuation lines must use value style"
                )


def check_review_detail_page_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/review-detail-pages/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    if vector.get("name") != rel:
        errors.append(f"{vector_path}: name mismatch")
    if vector.get("format") != "review-detail-pages-v0":
        errors.append(f"{vector_path}: format mismatch")
    if vector.get("display_profile") != "ascii-safe-codepoint-fallback-v0":
        errors.append(f"{vector_path}: display_profile mismatch")

    source_name = vector.get("source_review_vector")
    if not isinstance(source_name, str):
        errors.append(f"{vector_path}: source_review_vector must be a string")
        return
    source = load_required_json(f"vectors/review/{source_name}.json", errors)
    if source is None:
        return
    review = source.get("review")
    if not isinstance(review, dict):
        errors.append(f"{vector_path}: source review must be an object")
        return

    expected_screen = expected_screen_review(source["request"])
    screen_name = vector.get("source_screen_review_vector")
    if screen_name is not None:
        if not isinstance(screen_name, str):
            errors.append(f"{vector_path}: source_screen_review_vector must be a string")
            return
        screen = load_required_json(f"vectors/review-screens/{screen_name}.json", errors)
        if screen is None:
            return
        if screen.get("screen_review") != expected_screen:
            errors.append(f"{vector_path}: source_screen_review_vector mismatch")
    if vector.get("approval_digest") != expected_screen.get("approval_digest"):
        errors.append(f"{vector_path}: approval_digest mismatch")

    limits = check_display_limits(vector_path, vector.get("limits"), errors)
    if limits is None:
        return
    for field in ("max_compact_body_lines", "max_compact_line_chars"):
        if not isinstance(vector["limits"].get(field), int) or vector["limits"][field] <= 0:
            errors.append(f"{vector_path}: limits must contain positive integer compact display bounds")
            return
        limits[field] = vector["limits"][field]

    expected = expected_review_detail_pages(review, limits)
    pages = vector.get("pages")
    check_review_detail_page_contract(vector_path, pages, errors)
    if pages != expected:
        errors.append(f"{vector_path}: pages mismatch")


def expected_review_transcript(screen_review: dict, buttons: list[str], errors: list[str], rel: str) -> list[dict]:
    pages = screen_review["pages"]
    page_index = 0
    terminal = False
    transcript = []
    for button in buttons:
        if terminal:
            errors.append(f"vectors/review-transcripts/{rel}.json: button after terminal decision")
            break
        if button not in {"next", "approve", "reject"}:
            errors.append(f"vectors/review-transcripts/{rel}.json: unsupported button {button!r}")
            break

        frame = frame_for_page(pages[page_index], page_index, len(pages))
        decision = None
        approved = False
        if button == "next":
            if page_index + 1 < len(pages):
                page_index += 1
        elif button == "reject":
            decision = False
            terminal = True
        else:
            if page_index != len(pages) - 1:
                errors.append(f"vectors/review-transcripts/{rel}.json: approval before final page")
                break
            decision = True
            approved = True
            terminal = True

        transcript.append(
            {
                "frame": frame,
                "button": button,
                "decision": decision,
                "approved_for_signing": approved,
            }
        )
    return transcript


def detail_frame_for_page(page: dict, logical_page_has_scroll: bool, limits: dict) -> dict:
    action_hint = "Next" if page["action"] == "next" else "Approve / Reject"
    if logical_page_has_scroll and action_hint == "Next":
        action_hint = "Next/Scroll"
    lines, styles = bounded_detail_frame_body_lines(page, limits)
    return {
        "title": page["title"],
        "page_indicator": page["page_indicator"],
        "body_lines": lines,
        "action_hint": action_hint,
        "body_line_styles": styles,
    }


def detail_frame_compact_style(style: str) -> bool:
    return style in {"meta", "value"}


def bounded_detail_frame_body_lines(page: dict, limits: dict) -> tuple[list[str], list[str]]:
    wrapped: list[str] = []
    styles: list[str] = []
    has_compact_style = False
    page_styles = page.get("body_line_styles", [])
    for index, line in enumerate(page.get("lines", [])):
        style = page_styles[index] if index < len(page_styles) else "normal"
        has_compact_style = has_compact_style or detail_frame_compact_style(style)
        width = limits["max_compact_line_chars"] if detail_frame_compact_style(style) else limits["max_line_chars"]
        parts = split_exact_display_lines(str(line), width)
        wrapped.extend(parts)
        styles.extend([style] * len(parts))
    max_lines = limits["max_compact_body_lines"] if has_compact_style else limits["max_body_lines"]
    if len(wrapped) > max_lines:
        wrapped = wrapped[:max_lines]
        styles = styles[:max_lines]
        width = (
            limits["max_compact_line_chars"]
            if styles and detail_frame_compact_style(styles[-1])
            else limits["max_line_chars"]
        )
        wrapped[-1] = truncate_for_display(wrapped[-1], width, force_ellipsis=True)
    for index, line in enumerate(wrapped):
        width = (
            limits["max_compact_line_chars"]
            if index < len(styles) and detail_frame_compact_style(styles[index])
            else limits["max_line_chars"]
        )
        wrapped[index] = truncate_for_display(line, width)
    return wrapped, styles


def detail_logical_ranges(pages: list[dict]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    current_id: str | None = None
    for index, page in enumerate(pages):
        page_id = str(page.get("logical_page_id") or f"__page_{index}")
        if page_id != current_id:
            ranges.append((index, 1))
            current_id = page_id
        else:
            start, count = ranges[-1]
            ranges[-1] = (start, count + 1)
    return ranges


def expected_detail_review_transcript(
    detail_pages: list[dict],
    buttons: list[str],
    limits: dict,
    errors: list[str],
    rel: str,
) -> list[dict]:
    logical_ranges = detail_logical_ranges(detail_pages)
    logical_page_index = 0
    scroll_page_offset = 0
    seen_logical_pages = {0}
    terminal = False
    transcript = []
    for button in buttons:
        if terminal:
            errors.append(f"vectors/review-transcripts/{rel}.json: button after terminal decision")
            break
        if button not in {"next", "scroll", "approve", "reject"}:
            errors.append(f"vectors/review-transcripts/{rel}.json: unsupported button {button!r}")
            break

        start, count = logical_ranges[logical_page_index]
        page_index = start + scroll_page_offset
        page = detail_pages[page_index]
        frame = detail_frame_for_page(page, count > 1, limits)
        decision = None
        approved = False
        if button == "next":
            logical_page_index = (logical_page_index + 1) % len(logical_ranges)
            scroll_page_offset = 0
            seen_logical_pages.add(logical_page_index)
        elif button == "scroll":
            if count > 1:
                scroll_page_offset = (scroll_page_offset + 1) % count
        elif button == "reject":
            decision = False
            terminal = True
        else:
            if page.get("action") != "approve_or_reject" or len(seen_logical_pages) != len(logical_ranges):
                errors.append(f"vectors/review-transcripts/{rel}.json: approval before final page")
                break
            decision = True
            approved = True
            terminal = True

        transcript.append(
            {
                "frame": frame,
                "button": button,
                "decision": decision,
                "approved_for_signing": approved,
            }
        )
    return transcript


def check_review_transcript_vector(rel: str, errors: list[str]) -> None:
    vector = load_required_json(f"vectors/review-transcripts/{rel}.json", errors)
    if vector is None:
        return
    if vector.get("name") != rel:
        errors.append(f"vectors/review-transcripts/{rel}.json: name mismatch")
    if vector.get("format") != "qr-review-transcript-v0":
        errors.append(f"vectors/review-transcripts/{rel}.json: format mismatch")

    source_vector_name = vector.get("source_vector")
    if not isinstance(source_vector_name, str):
        errors.append(f"vectors/review-transcripts/{rel}.json: source_vector must be a string")
        return
    source_vector = load_required_json(f"vectors/transports/{source_vector_name}.json", errors)
    if source_vector is None:
        return

    review_mode = vector.get("review_mode", "screen")
    if review_mode not in {"screen", "detail"}:
        errors.append(f"vectors/review-transcripts/{rel}.json: review_mode must be screen or detail")
        return

    request = vector.get("request")
    if not isinstance(request, dict):
        errors.append(f"vectors/review-transcripts/{rel}.json: request must be an object")
        return
    check_request_shape(Path(f"vectors/review-transcripts/{rel}.json"), request, errors)
    if request != source_vector.get("decoded"):
        errors.append(f"vectors/review-transcripts/{rel}.json: request must match source QR vector")
    if vector.get("qr_envelope") != source_vector.get("envelope"):
        errors.append(f"vectors/review-transcripts/{rel}.json: qr_envelope mismatch")

    buttons = vector.get("buttons")
    if not isinstance(buttons, list) or not all(isinstance(button, str) for button in buttons):
        errors.append(f"vectors/review-transcripts/{rel}.json: buttons must be a string list")
        return
    if review_mode == "screen":
        screen_review_name = vector.get("screen_review_vector")
        if not isinstance(screen_review_name, str):
            errors.append(f"vectors/review-transcripts/{rel}.json: screen_review_vector must be a string")
            return
        screen_vector = load_required_json(f"vectors/review-screens/{screen_review_name}.json", errors)
        if screen_vector is None:
            return
        if request != screen_vector.get("request"):
            errors.append(f"vectors/review-transcripts/{rel}.json: request must match review-screen vector")
        if vector.get("approval_digest") != screen_vector.get("screen_review", {}).get("approval_digest"):
            errors.append(f"vectors/review-transcripts/{rel}.json: approval_digest mismatch")
        expected = expected_review_transcript(screen_vector["screen_review"], buttons, errors, rel)
    else:
        detail_review_name = vector.get("detail_review_vector")
        if not isinstance(detail_review_name, str):
            errors.append(f"vectors/review-transcripts/{rel}.json: detail_review_vector must be a string")
            return
        detail_vector = load_required_json(f"vectors/review-detail-pages/{detail_review_name}.json", errors)
        if detail_vector is None:
            return
        source_review_name = detail_vector.get("source_review_vector")
        source_review = load_required_json(f"vectors/review/{source_review_name}.json", errors)
        if source_review is None:
            return
        if request != source_review.get("request"):
            errors.append(f"vectors/review-transcripts/{rel}.json: request must match detail review source")
        if vector.get("approval_digest") != detail_vector.get("approval_digest"):
            errors.append(f"vectors/review-transcripts/{rel}.json: approval_digest mismatch")
        pages = detail_vector.get("pages")
        check_review_detail_page_contract(f"vectors/review-transcripts/{rel}.json", pages, errors)
        if not isinstance(pages, list):
            return
        limits = detail_vector.get("limits")
        if not isinstance(limits, dict):
            errors.append(f"vectors/review-transcripts/{rel}.json: detail vector limits must be an object")
            return
        expected = expected_detail_review_transcript(pages, buttons, limits, errors, rel)
    if vector.get("transcript") != expected:
        errors.append(f"vectors/review-transcripts/{rel}.json: transcript mismatch")


def compact_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


NIP46_PERMISSION_METHODS = {
    "sign_event",
    "nip04_encrypt",
    "nip04_decrypt",
    "nip44_encrypt",
    "nip44_decrypt",
    "get_public_key",
    "ping",
    "switch_relays",
}


def parse_nip46_permissions(value: str, vector_path: str, errors: list[str]) -> list[dict]:
    if value.strip() == "":
        return []
    parsed = []
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item:
            errors.append(f"{vector_path}: NIP-46 permission entries must be non-empty")
            continue
        parts = item.split(":")
        if len(parts) > 2 or not parts[0]:
            errors.append(f"{vector_path}: NIP-46 permission format is invalid")
            continue
        method = parts[0]
        parameter = parts[1] if len(parts) == 2 else None
        if method == "connect":
            errors.append(f"{vector_path}: NIP-46 permissions must not request connect")
            continue
        if method not in NIP46_PERMISSION_METHODS:
            errors.append(f"{vector_path}: unsupported permission method: {method}")
            continue
        if method == "sign_event" and parameter is not None:
            if not parameter.isdigit():
                errors.append(f"{vector_path}: sign_event permission kind must be numeric")
                continue
            event_kind = int(parameter)
            parsed.append({"method": method, "parameter": parameter, "event_kind": event_kind})
            continue
        if parameter is not None:
            errors.append(f"{vector_path}: permission method does not accept a parameter: {method}")
            continue
        parsed.append({"method": method})
    return parsed


def decode_unpadded_base64url(payload: object, vector_path: str, label: str, errors: list[str]) -> bytes | None:
    if not isinstance(payload, str) or not payload:
        errors.append(f"{vector_path}: {label} payload must be a non-empty string")
        return None
    if "=" in payload:
        errors.append(f"{vector_path}: {label} payload must be unpadded base64url")
        return None
    if not B64URL_RE.fullmatch(payload):
        errors.append(f"{vector_path}: {label} payload must be base64url")
        return None
    padding = "=" * ((4 - len(payload) % 4) % 4)
    try:
        return base64.b64decode(
            f"{payload}{padding}".encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except binascii.Error:
        errors.append(f"{vector_path}: {label} payload must decode as base64url")
        return None


def check_qr_envelope_payload(vector_path: str, envelope: object, errors: list[str]) -> None:
    limits = implementation_limit_values()
    if not isinstance(envelope, str):
        errors.append(f"{vector_path}: QR envelope must be a string")
        return
    if not envelope.startswith(QR_PREFIX):
        errors.append(f"{vector_path}: QR envelope requires nsealr1 prefix")
        return
    payload = envelope[len(QR_PREFIX) :]
    decoded = decode_unpadded_base64url(payload, vector_path, "QR envelope", errors)
    if decoded is None:
        return
    if len(decoded) > limits["max_static_qr_decoded_json_bytes"]:
        errors.append(f"{vector_path}: QR decoded JSON exceeds max_static_qr_decoded_json_bytes")
    try:
        decoded_text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"{vector_path}: QR envelope payload must be valid UTF-8")
        return
    try:
        decoded_json = json.loads(decoded_text)
    except json.JSONDecodeError:
        errors.append(f"{vector_path}: QR envelope payload must be JSON")
        return
    check_request_shape(Path(vector_path), decoded_json, errors)


def parse_animated_qr_frame(vector_path: str, frame: object, errors: list[str]) -> tuple[str, int, int, str] | None:
    limits = implementation_limit_values()
    if not isinstance(frame, str):
        errors.append(f"{vector_path}: animated QR frame must be a string")
        return None
    if not frame.startswith(ANIMATED_QR_PREFIX):
        errors.append(f"{vector_path}: animated QR frame requires nsealr1a prefix")
        return None
    parts = frame.split(":")
    if len(parts) != 5 or parts[0] != "nsealr1a":
        errors.append(f"{vector_path}: animated QR frame is malformed")
        return None
    digest, index_total, chunk, checksum = parts[1], parts[2], parts[3], parts[4]
    if not HEX32_RE.fullmatch(digest):
        errors.append(f"{vector_path}: animated QR digest must be 32-byte lowercase hex")
        return None
    if not HEX8_RE.fullmatch(checksum):
        errors.append(f"{vector_path}: animated QR checksum must be 8-byte lowercase hex")
        return None
    if "/" not in index_total:
        errors.append(f"{vector_path}: animated QR index must use index/total")
        return None
    index_text, total_text = index_total.split("/", 1)
    if not index_text.isdecimal() or not total_text.isdecimal():
        errors.append(f"{vector_path}: animated QR index and total must be decimal")
        return None
    index = int(index_text)
    total = int(total_text)
    if index < 1 or total < 1 or index > total:
        errors.append(f"{vector_path}: animated QR frame index is out of range")
        return None
    if total > limits["max_animated_qr_frame_count"]:
        errors.append(f"{vector_path}: animated QR frame count exceeds max_animated_qr_frame_count")
    if not B64URL_RE.fullmatch(chunk):
        errors.append(f"{vector_path}: animated QR chunk must be unpadded base64url")
        return None
    if len(chunk) > limits["max_animated_qr_frame_payload_chars"]:
        errors.append(f"{vector_path}: animated QR chunk exceeds max_animated_qr_frame_payload_chars")
    expected_checksum = animated_qr_checksum(digest, index, total, chunk)
    if checksum != expected_checksum:
        errors.append(f"{vector_path}: animated QR frame checksum mismatch")
    return digest, index, total, chunk


def check_animated_qr_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/transports/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    limits = implementation_limit_values()
    if vector.get("format") != "qr-animated-envelope-v0":
        errors.append(f"{vector_path}: format mismatch")
    if vector.get("prefix") != ANIMATED_QR_PREFIX:
        errors.append(f"{vector_path}: prefix mismatch")
    decoded = vector.get("decoded")
    if not isinstance(decoded, dict):
        errors.append(f"{vector_path}: decoded must be an object")
        return
    decoded_bytes = compact_json(decoded).encode("utf-8")
    if len(decoded_bytes) > limits["max_animated_qr_decoded_json_bytes"]:
        errors.append(f"{vector_path}: decoded JSON exceeds max_animated_qr_decoded_json_bytes")
    digest = sha256_hex(decoded_bytes)
    if vector.get("decoded_json_sha256") != digest:
        errors.append(f"{vector_path}: decoded_json_sha256 mismatch")
    payload = base64.urlsafe_b64encode(decoded_bytes).decode("ascii").rstrip("=")
    if vector.get("payload_base64url") != payload:
        errors.append(f"{vector_path}: payload_base64url mismatch")
    chunk_size = vector.get("chunk_size_chars")
    if not isinstance(chunk_size, int) or chunk_size <= 0:
        errors.append(f"{vector_path}: chunk_size_chars must be a positive integer")
        return
    if chunk_size > limits["max_animated_qr_frame_payload_chars"]:
        errors.append(f"{vector_path}: chunk_size_chars exceeds max_animated_qr_frame_payload_chars")
    expected_frames = animated_qr_frames(decoded, chunk_size)
    if vector.get("frames") != expected_frames:
        errors.append(f"{vector_path}: frames mismatch")
    frames = vector.get("frames")
    if not isinstance(frames, list) or not frames:
        errors.append(f"{vector_path}: frames must be a non-empty list")
        return
    parsed = [parse_animated_qr_frame(vector_path, frame, errors) for frame in frames]
    if any(item is None for item in parsed):
        return
    parsed_frames = [item for item in parsed if item is not None]
    digests = {item[0] for item in parsed_frames}
    totals = {item[2] for item in parsed_frames}
    if digests != {digest}:
        errors.append(f"{vector_path}: frame digest set mismatch")
    if len(totals) != 1:
        errors.append(f"{vector_path}: frame total mismatch")
        return
    total = totals.pop()
    indices = sorted(item[1] for item in parsed_frames)
    if indices != list(range(1, total + 1)):
        errors.append(f"{vector_path}: frames must be unique and contiguous")
    reassembled_payload = "".join(chunk for _, _, _, chunk in sorted(parsed_frames, key=lambda item: item[1]))
    if reassembled_payload != payload:
        errors.append(f"{vector_path}: reassembled payload mismatch")
    reassembled = decode_unpadded_base64url(reassembled_payload, vector_path, "animated QR", errors)
    if reassembled is not None and sha256_hex(reassembled) != digest:
        errors.append(f"{vector_path}: reassembled decoded digest mismatch")
    check_response_shape(Path(vector_path), decoded, errors)


def check_static_qr_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/transports/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    if vector.get("format") != "qr-envelope-v0":
        errors.append(f"{vector_path}: format mismatch")
    if vector.get("prefix") != QR_PREFIX:
        errors.append(f"{vector_path}: prefix mismatch")
    decoded = vector.get("decoded")
    if not isinstance(decoded, dict):
        errors.append(f"{vector_path}: decoded must be an object")
        return
    check_request_shape(Path(vector_path), decoded, errors)
    payload = base64url_json(decoded)
    if vector.get("payload_base64url") != payload:
        errors.append(f"{vector_path}: payload_base64url mismatch")
    if vector.get("envelope") != f"{QR_PREFIX}{payload}":
        errors.append(f"{vector_path}: envelope mismatch")


def check_serial_frame_payload(vector_path: str, frame: object, errors: list[str]) -> None:
    limits = implementation_limit_values()
    if not isinstance(frame, str):
        errors.append(f"{vector_path}: serial frame must be a string")
        return
    if utf8_size(frame) > limits["max_serial_frame_bytes"]:
        errors.append(f"{vector_path}: serial frame exceeds max_serial_frame_bytes")
    if not frame.startswith(SERIAL_PREFIX):
        errors.append(f"{vector_path}: serial frame requires nsealr1f prefix")
        return
    if not frame.endswith("\n"):
        errors.append(f"{vector_path}: serial frame must end with newline")
    body = frame[len(SERIAL_PREFIX) :].rstrip("\n")
    parts = body.split(":")
    if len(parts) != 3:
        errors.append(f"{vector_path}: serial frame must contain type, payload, and checksum")
        return
    frame_type, payload, checksum = parts
    if frame_type not in {"request", "response", "error"}:
        errors.append(f"{vector_path}: unsupported serial frame type")
    if not re.fullmatch(r"^[0-9a-f]{16}$", checksum):
        errors.append(f"{vector_path}: serial checksum must be 16 lowercase hex characters")
    expected_checksum = serial_checksum(frame_type, payload)
    if checksum != expected_checksum:
        errors.append(f"{vector_path}: serial checksum mismatch")
    decoded = decode_unpadded_base64url(payload, vector_path, "serial frame", errors)
    if decoded is None:
        return
    try:
        decoded_text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"{vector_path}: serial frame payload must be valid UTF-8")
        return
    try:
        decoded_json = json.loads(decoded_text)
    except json.JSONDecodeError:
        errors.append(f"{vector_path}: serial frame payload must be JSON")
        return
    if frame_type == "request":
        check_request_shape(Path(vector_path), decoded_json, errors)
    elif frame_type == "response":
        check_response_shape(Path(vector_path), decoded_json, errors)


def check_invalid_nip46_payload(vector_path: str, vector: dict, errors: list[str]) -> None:
    message = check_nip46_request_message(vector_path, vector.get("request_message"), errors)
    if message is None:
        return
    method = message.get("method")
    if method == "connect":
        expected_nip46_connect_intent(vector_path, message, errors)
        return
    expected_nip46_permission_requirement(vector_path, message, errors)


def check_invalid_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/invalid/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    if vector.get("name") != rel:
        errors.append(f"{vector_path}: name mismatch")
    if vector.get("format") != "pre-signing-invalid-vector-v0":
        errors.append(f"{vector_path}: format mismatch")
    expected_error = vector.get("expected_error")
    if not isinstance(expected_error, str) or not expected_error:
        errors.append(f"{vector_path}: expected_error must be a non-empty string")
        return

    rejection_errors: list[str] = []
    category = vector.get("category")
    if category == "signing-request":
        check_request_shape(Path(vector_path), vector.get("request"), rejection_errors)
    elif category == "qr-envelope":
        check_qr_envelope_payload(vector_path, vector.get("envelope"), rejection_errors)
    elif category == "serial-frame":
        check_serial_frame_payload(vector_path, vector.get("frame"), rejection_errors)
    elif category == "response":
        check_response_shape(Path(vector_path), vector.get("response"), rejection_errors)
    elif category == "nip46":
        check_invalid_nip46_payload(vector_path, vector, rejection_errors)
    elif category == "nip46-policy-file":
        policy = vector.get("policy_file")
        if not isinstance(policy, dict):
            rejection_errors.append(f"{vector_path}: policy_file must be an object")
        else:
            if policy.get("format") != "nsealr-nip46-policy-v0":
                rejection_errors.append(f"{vector_path}: format mismatch")
            approved_permissions = policy.get("approved_permissions")
            if not isinstance(approved_permissions, list):
                rejection_errors.append(f"{vector_path}: approved_permissions must be a list")
            else:
                for permission in approved_permissions:
                    normalized_nip46_permission(vector_path, permission, rejection_errors)
    else:
        errors.append(f"{vector_path}: unsupported invalid-vector category {category!r}")
        return

    if not rejection_errors:
        errors.append(f"{vector_path}: invalid vector unexpectedly passed")
        return
    observed = "\n".join(rejection_errors)
    if expected_error not in observed:
        errors.append(f"{vector_path}: expected error {expected_error!r} not observed in {observed!r}")


def check_nip46_connect_intent(vector_path: str, vector: dict, message: dict, errors: list[str]) -> None:
    expected = expected_nip46_connect_intent(vector_path, message, errors)
    if expected is None:
        return
    if vector.get("connect_intent") != expected:
        errors.append(f"{vector_path}: connect_intent mismatch")
    expected_review = expected_nip46_connect_review(expected)
    if vector.get("connect_review") != expected_review:
        errors.append(f"{vector_path}: connect_review mismatch")
    for forbidden in ("nsealr_request", "nsealr_response", "response_message", "local_response_message"):
        if forbidden in vector:
            errors.append(f"{vector_path}: connect must not include {forbidden}")
    for forbidden in ("permission_requirement", "permission_checks"):
        if forbidden in vector:
            errors.append(f"{vector_path}: connect must not include {forbidden}")


def expected_nip46_connect_intent(vector_path: str, message: dict, errors: list[str]) -> dict | None:
    params = message.get("params", [])
    if len(params) < 1 or len(params) > 3:
        errors.append(f"{vector_path}: connect requires remote-signer pubkey plus optional secret and permissions")
        return None
    remote_pubkey = params[0]
    if not isinstance(remote_pubkey, str) or not HEX32_RE.fullmatch(remote_pubkey):
        errors.append(f"{vector_path}: connect remote-signer pubkey must be 32-byte lowercase hex")
        return None
    expected = {
        "id": message["id"],
        "remote_signer_pubkey": remote_pubkey,
        "requested_permissions": parse_nip46_permissions(params[2] if len(params) > 2 else "", vector_path, errors),
    }
    if len(params) > 1 and params[1] != "":
        expected["secret"] = params[1]
    return expected


def expected_nip46_connect_review(intent: dict) -> dict:
    permissions = intent.get("requested_permissions", [])
    permission_lines = [permission_label(permission) for permission in permissions]
    return {
        "format": "nsealr-nip46-connect-review-v0",
        "id": intent["id"],
        "remote_signer_pubkey": intent["remote_signer_pubkey"],
        "secret_present": "secret" in intent,
        "requested_permissions": permissions,
        "pages": [
            {
                "title": "Connect",
                "page_indicator": "Page 1/2",
                "body_lines": [
                    "Remote signer",
                    intent["remote_signer_pubkey"],
                    f"Secret: {'provided' if 'secret' in intent else 'none'}",
                ],
            },
            {
                "title": "Permissions",
                "page_indicator": "Page 2/2",
                "body_lines": permission_lines if permission_lines else ["No permissions requested"],
            },
        ],
    }


def normalized_nip46_permission(vector_path: str, value: object, errors: list[str]) -> dict | None:
    if not isinstance(value, dict):
        errors.append(f"{vector_path}: permission entries must be objects")
        return None
    method = value.get("method")
    if not isinstance(method, str) or method not in NIP46_PERMISSION_METHODS:
        errors.append(f"{vector_path}: permission method is invalid")
        return None
    if method == "sign_event":
        if "parameter" not in value:
            if set(value) != {"method"}:
                errors.append(f"{vector_path}: broad sign_event permission must only include method")
                return None
            return {"method": method}
        parameter = value.get("parameter")
        event_kind = value.get("event_kind")
        if (
            set(value) != {"method", "parameter", "event_kind"}
            or not isinstance(parameter, str)
            or not parameter.isdigit()
            or not isinstance(event_kind, int)
            or event_kind != int(parameter)
        ):
            errors.append(f"{vector_path}: sign_event permission parameter must match event_kind")
            return None
        return {"method": method, "parameter": parameter, "event_kind": event_kind}
    if set(value) != {"method"}:
        errors.append(f"{vector_path}: non-sign_event permission must only include method")
        return None
    return {"method": method}


def nip46_permission_matches_requirement(permission: dict, requirement: dict) -> bool:
    if permission.get("method") != requirement.get("method"):
        return False
    if requirement.get("method") != "sign_event":
        return "parameter" not in permission
    if "parameter" not in permission:
        return True
    return permission.get("event_kind") == requirement.get("event_kind")


def check_nip46_permission_policy(vector_path: str, vector: dict, expected_requirement: dict, errors: list[str]) -> None:
    requirement = normalized_nip46_permission(vector_path, vector.get("permission_requirement"), errors)
    if requirement != expected_requirement:
        errors.append(f"{vector_path}: permission_requirement mismatch")

    checks = vector.get("permission_checks")
    if not isinstance(checks, list) or not checks:
        errors.append(f"{vector_path}: permission_checks must be a non-empty list")
        return
    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            errors.append(f"{vector_path}: permission_checks[{index}] must be an object")
            continue
        granted = check.get("granted_permissions")
        if not isinstance(granted, list):
            errors.append(f"{vector_path}: permission_checks[{index}].granted_permissions must be a list")
            continue
        granted_permissions = [
            permission
            for permission in (
                normalized_nip46_permission(vector_path, permission, errors) for permission in granted
            )
            if permission is not None
        ]
        expected_permitted = any(
            nip46_permission_matches_requirement(permission, expected_requirement) for permission in granted_permissions
        )
        if check.get("permitted") is not expected_permitted:
            errors.append(f"{vector_path}: permission_checks[{index}].permitted mismatch")


def check_nip46_request_message(vector_path: str, message: object, errors: list[str]) -> dict | None:
    if not isinstance(message, dict):
        errors.append(f"{vector_path}: request_message must be an object")
        return None
    if json_utf8_size(message) > implementation_limit_values()["max_nip46_decrypted_message_json_bytes"]:
        errors.append(f"{vector_path}: NIP-46 decrypted message JSON exceeds max_nip46_decrypted_message_json_bytes")
    if not isinstance(message.get("id"), str) or not REQUEST_ID_RE.fullmatch(message["id"]):
        errors.append(f"{vector_path}: request_message id is invalid")
    if message.get("method") not in {"connect", "get_public_key", "sign_event", "ping"}:
        errors.append(f"{vector_path}: unsupported NIP-46 method")
    if not isinstance(message.get("params"), list) or not all(isinstance(item, str) for item in message["params"]):
        errors.append(f"{vector_path}: request_message params must be a string array")
    return message


def expected_nip46_permission_requirement(vector_path: str, message: dict, errors: list[str]) -> dict | None:
    method = message.get("method")
    params = message.get("params", [])
    if method == "ping":
        if params:
            errors.append(f"{vector_path}: ping params must be empty")
            return None
        return {"method": "ping"}
    if method == "get_public_key":
        if params:
            errors.append(f"{vector_path}: get_public_key params must be empty")
            return None
        return {"method": "get_public_key"}
    if method == "sign_event":
        if len(params) != 1:
            errors.append(f"{vector_path}: sign_event must have one JSON string param")
            return None
        try:
            event_template = json.loads(params[0])
        except json.JSONDecodeError:
            errors.append(f"{vector_path}: sign_event param must be valid JSON")
            return None
        request_errors = request_shape_errors(
            Path(vector_path),
            {
                "version": 1,
                "request_id": message.get("id"),
                "method": "sign_event",
                "params": {
                    "event_template": event_template,
                },
            },
        )
        if request_errors:
            errors.extend(request_errors)
            return None
        if not isinstance(event_template, dict) or type(event_template.get("kind")) is not int:
            errors.append(f"{vector_path}: sign_event event kind is invalid")
            return None
        return {
            "method": "sign_event",
            "parameter": str(event_template["kind"]),
            "event_kind": event_template["kind"],
        }
    return None


def expected_nsealr_request_from_nip46_message(
    vector_path: str, message: dict, errors: list[str]
) -> dict | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params", [])
    if method == "get_public_key":
        return {
            "version": 1,
            "request_id": request_id,
            "method": "get_public_key",
        }
    if method == "sign_event":
        if len(params) != 1:
            return None
        try:
            event_template = json.loads(params[0])
        except json.JSONDecodeError:
            return None
        return {
            "version": 1,
            "request_id": request_id,
            "method": "sign_event",
            "params": {
                "event_template": event_template,
            },
        }
    errors.append(f"{vector_path}: cannot create nSealr request for NIP-46 method")
    return None


def permission_label(requirement: dict) -> str:
    if requirement.get("method") == "sign_event" and "parameter" in requirement:
        return f"sign_event:{requirement['parameter']}"
    return str(requirement.get("method"))


def expected_nip46_bridge_decision(
    vector_path: str,
    message: dict,
    granted_permissions: list[dict],
    errors: list[str],
) -> dict | None:
    method = message.get("method")
    request_id = message.get("id")
    if method == "connect":
        connect_intent = expected_nip46_connect_intent(vector_path, message, errors)
        if connect_intent is None:
            return None
        return {
            "type": "connect_review",
            "connect_intent": connect_intent,
        }

    requirement = expected_nip46_permission_requirement(vector_path, message, errors)
    if requirement is None:
        return None
    permitted = any(
        nip46_permission_matches_requirement(permission, requirement) for permission in granted_permissions
    )
    if not permitted:
        return {
            "type": "permission_denied",
            "permission_requirement": requirement,
            "response_message": {
                "id": request_id,
                "error": f"permission_denied: request requires approved permission {permission_label(requirement)}",
            },
        }
    if method == "ping":
        return {
            "type": "local_response",
            "permission_requirement": requirement,
            "response_message": {
                "id": request_id,
                "result": "pong",
            },
        }

    nsealr_request = expected_nsealr_request_from_nip46_message(vector_path, message, errors)
    if nsealr_request is None:
        return None
    return {
        "type": "signer_request",
        "permission_requirement": requirement,
        "nsealr_request": nsealr_request,
    }


def check_nip46_bridge_decisions(
    vector_path: str,
    vector: dict,
    message: dict,
    errors: list[str],
) -> None:
    bridge_decisions = vector.get("bridge_decisions")
    if not isinstance(bridge_decisions, list) or not bridge_decisions:
        errors.append(f"{vector_path}: bridge_decisions must be a non-empty list")
        return
    for index, check in enumerate(bridge_decisions):
        if not isinstance(check, dict):
            errors.append(f"{vector_path}: bridge_decisions[{index}] must be an object")
            continue
        granted = check.get("granted_permissions")
        if not isinstance(granted, list):
            errors.append(f"{vector_path}: bridge_decisions[{index}].granted_permissions must be a list")
            continue
        granted_permissions = [
            permission
            for permission in (
                normalized_nip46_permission(vector_path, permission, errors) for permission in granted
            )
            if permission is not None
        ]
        expected = expected_nip46_bridge_decision(vector_path, message, granted_permissions, errors)
        if expected is not None and check.get("decision") != expected:
            errors.append(f"{vector_path}: bridge_decisions[{index}].decision mismatch")


def check_nip46_policy_file_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/nip46-policy-files/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    if vector.get("format") != "nsealr-nip46-policy-v0":
        errors.append(f"{vector_path}: format mismatch")
    approved_permissions = vector.get("approved_permissions")
    if not isinstance(approved_permissions, list):
        errors.append(f"{vector_path}: approved_permissions must be a list")
        return
    for index, permission in enumerate(approved_permissions):
        normalized = normalized_nip46_permission(vector_path, permission, errors)
        if normalized is not None and permission != normalized:
            errors.append(f"{vector_path}: approved_permissions[{index}] must be normalized")


def compact_seedqr_hex_from_indexes(indexes: list[int], word_count: int) -> str:
    bit_stream = "".join(f"{index:011b}" for index in indexes)
    checksum_bits = 4 if word_count == 12 else 8
    entropy_bits = bit_stream[:-checksum_bits]
    return int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, "big").hex()


def check_seedqr_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/seedqr/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    if not isinstance(vector, dict):
        errors.append(f"{vector_path}: SeedQR vector must be an object")
        return
    if vector.get("format") != "nsealr-seedqr-vector-v0":
        errors.append(f"{vector_path}: format mismatch")
    if vector.get("name") != rel:
        errors.append(f"{vector_path}: name mismatch")
    if not isinstance(vector.get("source"), str) or not vector["source"]:
        errors.append(f"{vector_path}: source must be a non-empty string")
    word_count = vector.get("word_count")
    if word_count not in {12, 24}:
        errors.append(f"{vector_path}: word_count must be 12 or 24")
        return
    mnemonic = vector.get("mnemonic")
    if not isinstance(mnemonic, str) or len(mnemonic.split()) != word_count:
        errors.append(f"{vector_path}: mnemonic word count mismatch")
    digits = vector.get("standard_seedqr_digits")
    if not isinstance(digits, str) or not digits.isdigit() or len(digits) != word_count * 4:
        errors.append(f"{vector_path}: standard_seedqr_digits must contain four digits per word")
        return
    indexes = [int(digits[index : index + 4]) for index in range(0, len(digits), 4)]
    if any(index > 2047 for index in indexes):
        errors.append(f"{vector_path}: standard_seedqr_digits contains an out-of-range BIP-39 index")
    if vector.get("standard_word_indexes") != indexes:
        errors.append(f"{vector_path}: standard_word_indexes mismatch")
    compact = vector.get("compact_seedqr_hex")
    expected_hex_chars = 32 if word_count == 12 else 64
    if not isinstance(compact, str) or not re.fullmatch(r"[0-9a-f]+", compact) or len(compact) != expected_hex_chars:
        errors.append(f"{vector_path}: compact_seedqr_hex length or encoding mismatch")
    elif compact != compact_seedqr_hex_from_indexes(indexes, word_count):
        errors.append(f"{vector_path}: compact_seedqr_hex mismatch")
    scope = vector.get("compatibility_scope")
    if not isinstance(scope, str) or not scope:
        errors.append(f"{vector_path}: compatibility_scope must be a non-empty string")
    else:
        scope_lower = scope.lower()
        for required in ("bip-39", "nip-06", "not bitcoin descriptors", "xpubs", "psbts", "wallet policy"):
            if required not in scope_lower:
                errors.append(f"{vector_path}: compatibility_scope must mention {required}")


def check_feature_matrix_feature_shape(
    path: str,
    feature_id: str,
    feature: object,
    canonical_contracts: dict[str, str],
    errors: list[str],
) -> None:
    if feature_id not in FEATURE_IDS:
        errors.append(f"{path}: unknown feature {feature_id}")
    if not isinstance(feature, dict):
        errors.append(f"{path}: feature {feature_id} must be an object")
        return

    target = feature.get("target")
    current = feature.get("current")
    if target not in FEATURE_TARGETS:
        errors.append(f"{path}: feature {feature_id} target is unknown")
    if current not in FEATURE_CURRENT_STATUSES:
        errors.append(f"{path}: feature {feature_id} current status is unknown")

    contract_id = feature.get("contract_id")
    active_target = target in {"required", "optional", "research"}
    if active_target:
        if not isinstance(contract_id, str) or not contract_id:
            errors.append(f"{path}: feature {feature_id} active target requires contract_id")
        elif canonical_contracts.get(feature_id) != contract_id:
            errors.append(f"{path}: feature {feature_id} contract_id does not match canonical feature contract")
    elif "contract_id" in feature:
        errors.append(f"{path}: feature {feature_id} inactive target must not set contract_id")

    notes = feature.get("notes")
    if not isinstance(notes, str) or not notes:
        errors.append(f"{path}: feature {feature_id} notes must be a non-empty string")


def check_feature_matrix_shape(path: str, matrix: object, errors: list[str]) -> None:
    if not isinstance(matrix, dict):
        errors.append(f"{path}: feature matrix must be an object")
        return
    if matrix.get("format") != "nsealr-signer-feature-matrix-v0":
        errors.append(f"{path}: format mismatch")
    if matrix.get("name") != Path(path).stem:
        errors.append(f"{path}: name mismatch")

    features = matrix.get("features")
    if not isinstance(features, list):
        errors.append(f"{path}: features must be a list")
        return
    feature_ids: list[str] = []
    canonical_contracts: dict[str, str] = {}
    for index, feature in enumerate(features):
        feature_path = f"{path}: features[{index}]"
        if not isinstance(feature, dict):
            errors.append(f"{feature_path}: feature definition must be an object")
            continue
        feature_id = feature.get("id")
        if feature_id not in FEATURE_IDS:
            errors.append(f"{feature_path}: unknown feature id")
            continue
        feature_ids.append(feature_id)
        contract_id = feature.get("contract_id")
        if not isinstance(contract_id, str) or not contract_id:
            errors.append(f"{feature_path}: contract_id must be a non-empty string")
        else:
            canonical_contracts[feature_id] = contract_id
        behavior = feature.get("behavior")
        if not isinstance(behavior, str) or not behavior:
            errors.append(f"{feature_path}: behavior must be a non-empty string")
    if set(feature_ids) != FEATURE_IDS:
        errors.append(f"{path}: feature definitions must match the canonical feature id set")
    if len(feature_ids) != len(set(feature_ids)):
        errors.append(f"{path}: feature definitions contain duplicates")

    solutions = matrix.get("solutions")
    if not isinstance(solutions, dict):
        errors.append(f"{path}: solutions must be an object")
        return
    if set(solutions) != FEATURE_SOLUTION_IDS:
        errors.append(f"{path}: solutions must match the five first-class signer families")
        return

    active_contracts: dict[str, str] = {}
    for solution_id, solution in sorted(solutions.items()):
        solution_path = f"{path}: solutions.{solution_id}"
        if not isinstance(solution, dict):
            errors.append(f"{solution_path}: solution must be an object")
            continue
        if not isinstance(solution.get("label"), str) or not solution["label"]:
            errors.append(f"{solution_path}: label must be a non-empty string")
        if not isinstance(solution.get("repository"), str) or not solution["repository"]:
            errors.append(f"{solution_path}: repository must be a non-empty string")
        if not isinstance(solution.get("product_goal"), str) or not solution["product_goal"]:
            errors.append(f"{solution_path}: product_goal must be a non-empty string")
        solution_features = solution.get("features")
        if not isinstance(solution_features, dict):
            errors.append(f"{solution_path}: features must be an object")
            continue
        if set(solution_features) != FEATURE_IDS:
            errors.append(f"{solution_path}: features must match the canonical feature id set")
            continue
        for feature_id, feature in sorted(solution_features.items()):
            feature_path = f"{solution_path}.features.{feature_id}"
            check_feature_matrix_feature_shape(feature_path, feature_id, feature, canonical_contracts, errors)
            if not isinstance(feature, dict):
                continue
            target = feature.get("target")
            contract_id = feature.get("contract_id")
            if target in {"required", "optional", "research"} and isinstance(contract_id, str):
                previous = active_contracts.setdefault(feature_id, contract_id)
                if previous != contract_id:
                    errors.append(
                        f"{feature_path}: shared feature contract drift for {feature_id}"
                    )

    parity_targets: dict[str, object] | None = None
    for solution_id in ("raspberry_qr_vault", "esp32_qr_vault"):
        solution = solutions.get(solution_id)
        if not isinstance(solution, dict) or not isinstance(solution.get("features"), dict):
            continue
        current_targets = {
            feature_id: solution["features"].get(feature_id, {}).get("target")
            for feature_id in STATELESS_QR_PARITY_FEATURES
            if isinstance(solution["features"].get(feature_id), dict)
        }
        if parity_targets is None:
            parity_targets = current_targets
        elif current_targets != parity_targets:
            errors.append(f"{path}: stateless_qr_vault parity mismatch")


def check_feature_matrix_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/features/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    check_feature_matrix_shape(vector_path, vector, errors)


def check_nip46_response_message(vector_path: str, message: object, expected_id: str, errors: list[str]) -> dict | None:
    if not isinstance(message, dict):
        errors.append(f"{vector_path}: response_message must be an object")
        return None
    if message.get("id") != expected_id:
        errors.append(f"{vector_path}: response_message id mismatch")
    if "result" not in message and "error" not in message:
        errors.append(f"{vector_path}: response_message must include result or error")
    if "result" in message and "error" in message:
        errors.append(f"{vector_path}: response_message must not include both result and error")
    if "result" in message and not isinstance(message["result"], str):
        errors.append(f"{vector_path}: response_message result must be a string")
    if "error" in message and not isinstance(message["error"], str):
        errors.append(f"{vector_path}: response_message error must be a string")
    return message


def check_nip46_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/nip46/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    if vector.get("name") != rel:
        errors.append(f"{vector_path}: name mismatch")
    if vector.get("format") != "nip46-decrypted-payload-v0":
        errors.append(f"{vector_path}: format mismatch")

    message = check_nip46_request_message(vector_path, vector.get("request_message"), errors)
    if message is None:
        return
    request_id = message.get("id")
    if not isinstance(request_id, str):
        return
    method = message.get("method")
    params = message.get("params", [])
    if not isinstance(params, list):
        return

    check_nip46_bridge_decisions(vector_path, vector, message, errors)

    if method == "ping":
        if params:
            errors.append(f"{vector_path}: ping params must be empty")
        if "nsealr_request" in vector or "nsealr_response" in vector:
            errors.append(f"{vector_path}: ping must not include nSealr request/response")
        if vector.get("local_response_message") != {"id": request_id, "result": "pong"}:
            errors.append(f"{vector_path}: local_response_message mismatch")
        check_nip46_permission_policy(vector_path, vector, {"method": "ping"}, errors)
        return

    if method == "connect":
        check_nip46_connect_intent(vector_path, vector, message, errors)
        return

    nsealr_request = vector.get("nsealr_request")
    if not isinstance(nsealr_request, dict):
        errors.append(f"{vector_path}: nsealr_request must be an object")
        return
    check_request_shape(Path(vector_path), nsealr_request, errors)
    if nsealr_request.get("request_id") != request_id:
        errors.append(f"{vector_path}: nsealr_request request_id mismatch")
    if nsealr_request.get("method") != method:
        errors.append(f"{vector_path}: nsealr_request method mismatch")

    if method == "get_public_key" and params:
        errors.append(f"{vector_path}: get_public_key params must be empty")
    if method == "get_public_key":
        check_nip46_permission_policy(vector_path, vector, {"method": "get_public_key"}, errors)
    if method == "sign_event":
        if len(params) != 1:
            errors.append(f"{vector_path}: sign_event must have one JSON string param")
        else:
            try:
                event_template = json.loads(params[0])
            except json.JSONDecodeError:
                errors.append(f"{vector_path}: sign_event param must be valid JSON")
            else:
                if event_template != nsealr_request.get("params", {}).get("event_template"):
                    errors.append(f"{vector_path}: sign_event param must match nSealr event_template")
                if not isinstance(event_template, dict) or not isinstance(event_template.get("kind"), int):
                    errors.append(f"{vector_path}: sign_event event kind is invalid")
                else:
                    check_nip46_permission_policy(
                        vector_path,
                        vector,
                        {
                            "method": "sign_event",
                            "parameter": str(event_template["kind"]),
                            "event_kind": event_template["kind"],
                        },
                        errors,
                    )

    nsealr_response = vector.get("nsealr_response")
    if not isinstance(nsealr_response, dict):
        errors.append(f"{vector_path}: nsealr_response must be an object")
        return
    check_response_shape(Path(vector_path), nsealr_response, errors)
    if nsealr_response.get("request_id") != request_id:
        errors.append(f"{vector_path}: nsealr_response request_id mismatch")

    response_message = check_nip46_response_message(vector_path, vector.get("response_message"), request_id, errors)
    if response_message is None:
        return
    if nsealr_response.get("ok") is False:
        error = nsealr_response.get("error", {})
        if response_message.get("error") != f"{error.get('code')}: {error.get('message')}":
            errors.append(f"{vector_path}: response_message error mismatch")
        return

    result = nsealr_response.get("result", {})
    if method == "get_public_key":
        if response_message.get("result") != result.get("public_key"):
            errors.append(f"{vector_path}: public-key result mismatch")
    if method == "sign_event":
        if response_message.get("result") != compact_json(result.get("event")):
            errors.append(f"{vector_path}: signed-event result mismatch")


SMARTCARD_APDU_EXPECTATIONS = {
    "get-public-key": {
        "cla": "80",
        "ins": "10",
        "command_hex": "80100000",
        "status_word": "9000",
        "response_data_hex": lambda: load_json("vectors/keys/test-key-1.json")["public_key"],
    },
    "sign-event-id-kind-1-basic": {
        "cla": "80",
        "ins": "20",
        "event_id": lambda: load_json("vectors/events/kind-1-basic.json")["event_id"],
        "command_hex": lambda: f"8020000020{load_json('vectors/events/kind-1-basic.json')['event_id']}",
        "status_word": "9000",
        "expected_data_length": 64,
    },
    "sign-event-id-wrong-length": {
        "cla": "80",
        "ins": "20",
        "command_hex": "8020000001ff",
        "status_word": "6700",
        "response_hex": "6700",
    },
    "unsupported-cla": {
        "cla": "00",
        "ins": "10",
        "command_hex": "00100000",
        "status_word": "6e00",
        "response_hex": "6e00",
    },
    "unsupported-ins": {
        "cla": "80",
        "ins": "ff",
        "command_hex": "80ff0000",
        "status_word": "6d00",
        "response_hex": "6d00",
    },
}


def expected_apdu_value(value: object) -> object:
    if callable(value):
        return value()
    return value


def apdu_vector_status_word(vector: dict) -> str | None:
    status = vector.get("expected_status_word", vector.get("status_word"))
    return status if isinstance(status, str) else None


def check_smartcard_apdu_vector(rel: str, errors: list[str]) -> None:
    vector_path = f"vectors/smartcard/{rel}.json"
    vector = load_required_json(vector_path, errors)
    if vector is None:
        return
    expectation = SMARTCARD_APDU_EXPECTATIONS.get(rel)
    if expectation is None:
        errors.append(f"{vector_path}: unexpected smartcard APDU vector")
        return

    if vector.get("name") != rel:
        errors.append(f"{vector_path}: name mismatch")
    if vector.get("format") != "smartcard-apdu-v0":
        errors.append(f"{vector_path}: format mismatch")
    for field in ("cla", "ins", "event_id", "command_hex"):
        if field not in expectation:
            continue
        expected = expected_apdu_value(expectation[field])
        if vector.get(field) != expected:
            errors.append(f"{vector_path}: {field} mismatch")

    command_hex = vector.get("command_hex", "")
    if not isinstance(command_hex, str) or len(command_hex) % 2 != 0 or not APDU_HEX_RE.fullmatch(command_hex):
        errors.append(f"{vector_path}: command_hex must be even-length lowercase hex")

    expected_status = expected_apdu_value(expectation["status_word"])
    if apdu_vector_status_word(vector) != expected_status:
        errors.append(f"{vector_path}: status word mismatch")

    if "response_data_hex" in expectation:
        expected_response_data = expected_apdu_value(expectation["response_data_hex"])
        if vector.get("response_data_hex") != expected_response_data:
            errors.append(f"{vector_path}: response_data_hex mismatch")
        expected_response_hex = f"{expected_response_data}{expected_status}"
        if vector.get("response_hex") != expected_response_hex:
            errors.append(f"{vector_path}: response_hex mismatch")
    elif "response_hex" in expectation and vector.get("response_hex") != expectation["response_hex"]:
        errors.append(f"{vector_path}: response_hex mismatch")

    if "expected_data_length" in expectation and vector.get("expected_data_length") != expectation["expected_data_length"]:
        errors.append(f"{vector_path}: expected_data_length mismatch")


def main() -> int:
    errors: list[str] = []

    for schema in (
        "signing-request-v0.schema.json",
        "signing-response-v0.schema.json",
        "error-v0.schema.json",
        "nip46-policy-file-v0.schema.json",
        "account-descriptor-v0.schema.json",
        "policy-profile-v0.schema.json",
        "grant-descriptor-v0.schema.json",
        "policy-decision-vector-v0.schema.json",
        "route-selection-vector-v0.schema.json",
    ):
        load_json(f"schemas/{schema}")

    check_implementation_limits(errors)

    for path in sorted((ROOT / "examples").glob("request-*.json")):
        check_request_shape(path.relative_to(ROOT), load_json(str(path.relative_to(ROOT))), errors)

    for path in sorted((ROOT / "examples" / "invalid").glob("request-*.json")):
        invalid_errors = request_shape_errors(path.relative_to(ROOT), load_json(str(path.relative_to(ROOT))))
        if not invalid_errors:
            errors.append(f"{path.relative_to(ROOT)}: invalid request unexpectedly passed")

    for path in sorted((ROOT / "examples").glob("response-*.json")):
        check_response_shape(path.relative_to(ROOT), load_json(str(path.relative_to(ROOT))), errors)

    capability_request = load_required_json("examples/request-get-capabilities.json", errors)
    capability_response = load_required_json("examples/response-get-capabilities-esp32-s3-scaffold.json", errors)
    capability_vector = load_required_json("vectors/devices/esp32-s3-capabilities-scaffold.json", errors)
    signing_status_request = load_required_json("examples/request-get-signing-status.json", errors)
    signing_status_response = load_required_json("examples/response-get-signing-status-esp32-s3-scaffold.json", errors)
    signing_status_vector = load_required_json("vectors/devices/esp32-s3-signing-status-disabled.json", errors)
    public_key_request = load_required_json("examples/request-get-public-key.json", errors)
    public_key_response = load_required_json("examples/response-get-public-key.json", errors)
    public_key_vector = load_required_json("vectors/devices/esp32-s3-get-public-key-dev.json", errors)
    signing_disabled_response = load_required_json("examples/response-sign-event-disabled-esp32-s3-scaffold.json", errors)
    signing_disabled_vector = load_required_json("vectors/devices/esp32-s3-sign-event-disabled.json", errors)
    if capability_request is not None:
        if capability_request.get("method") != "get_capabilities":
            errors.append("examples/request-get-capabilities.json: method must be get_capabilities")
    if capability_request is not None and capability_response is not None:
        if capability_response.get("request_id") != capability_request.get("request_id"):
            errors.append("examples/response-get-capabilities-esp32-s3-scaffold.json: request_id mismatch")
        capabilities = capability_response.get("result", {}).get("capabilities", {})
        if capabilities.get("signing_enabled") is not False:
            errors.append("examples/response-get-capabilities-esp32-s3-scaffold.json: scaffold signing must be disabled")
        if capabilities.get("requires_physical_approval") is not True:
            errors.append("examples/response-get-capabilities-esp32-s3-scaffold.json: physical approval must be required")
        if "sign_event" not in capabilities.get("methods", []):
            errors.append("examples/response-get-capabilities-esp32-s3-scaffold.json: sign_event capability must be declared")
        if "get_signing_status" not in capabilities.get("methods", []):
            errors.append("examples/response-get-capabilities-esp32-s3-scaffold.json: get_signing_status capability must be declared")
    if capability_vector is not None and capability_request is not None and capability_response is not None:
        if capability_vector.get("request") != capability_request:
            errors.append("vectors/devices/esp32-s3-capabilities-scaffold.json: request mismatch")
        if capability_vector.get("response") != capability_response:
            errors.append("vectors/devices/esp32-s3-capabilities-scaffold.json: response mismatch")
    if signing_status_request is not None:
        if signing_status_request.get("method") != "get_signing_status":
            errors.append("examples/request-get-signing-status.json: method must be get_signing_status")
    if signing_status_request is not None and signing_status_response is not None:
        if signing_status_response.get("request_id") != signing_status_request.get("request_id"):
            errors.append("examples/response-get-signing-status-esp32-s3-scaffold.json: request_id mismatch")
        signing_status = signing_status_response.get("result", {}).get("signing_status", {})
        if signing_status.get("signing_enabled") is not False:
            errors.append("examples/response-get-signing-status-esp32-s3-scaffold.json: scaffold signing must be disabled")
        if signing_status.get("missing_gates") != ESP32_S3_SCAFFOLD_MISSING_SIGNING_GATES:
            errors.append("examples/response-get-signing-status-esp32-s3-scaffold.json: missing gate list mismatch")
        if signing_status.get("development_accepted_gates") != ESP32_S3_SCAFFOLD_DEVELOPMENT_ACCEPTED_SIGNING_GATES:
            errors.append("examples/response-get-signing-status-esp32-s3-scaffold.json: development accepted gate list mismatch")
    if signing_status_vector is not None and signing_status_request is not None and signing_status_response is not None:
        if signing_status_vector.get("request") != signing_status_request:
            errors.append("vectors/devices/esp32-s3-signing-status-disabled.json: request mismatch")
        if signing_status_vector.get("response") != signing_status_response:
            errors.append("vectors/devices/esp32-s3-signing-status-disabled.json: response mismatch")
    if public_key_request is not None:
        if public_key_request.get("method") != "get_public_key":
            errors.append("examples/request-get-public-key.json: method must be get_public_key")
    if public_key_request is not None and public_key_response is not None:
        if public_key_response.get("request_id") != public_key_request.get("request_id"):
            errors.append("examples/response-get-public-key.json: request_id mismatch")
    if public_key_vector is not None and public_key_request is not None and public_key_response is not None:
        if public_key_vector.get("request") != public_key_request:
            errors.append("vectors/devices/esp32-s3-get-public-key-dev.json: request mismatch")
        if public_key_vector.get("response") != public_key_response:
            errors.append("vectors/devices/esp32-s3-get-public-key-dev.json: response mismatch")
    if signing_disabled_response is not None:
        if signing_disabled_response.get("ok") is not False:
            errors.append("examples/response-sign-event-disabled-esp32-s3-scaffold.json: ok must be false")
        error = signing_disabled_response.get("error", {})
        if error.get("code") != "signing_disabled":
            errors.append("examples/response-sign-event-disabled-esp32-s3-scaffold.json: code must be signing_disabled")
        if error.get("retryable") is not False:
            errors.append("examples/response-sign-event-disabled-esp32-s3-scaffold.json: retryable must be false")
    if signing_disabled_vector is not None and signing_disabled_response is not None:
        if signing_disabled_vector.get("request") != load_json("examples/request-kind-1-basic.json"):
            errors.append("vectors/devices/esp32-s3-sign-event-disabled.json: request mismatch")
        if signing_disabled_vector.get("response") != signing_disabled_response:
            errors.append("vectors/devices/esp32-s3-sign-event-disabled.json: response mismatch")

    key = load_json("vectors/keys/test-key-1.json")
    if not HEX32_RE.fullmatch(key.get("public_key", "")):
        errors.append("vectors/keys/test-key-1.json: invalid public_key")
    if xonly_pubkey_from_secret(key.get("secret_key", "")) != key.get("public_key"):
        errors.append("vectors/keys/test-key-1.json: public_key mismatch")
    nip06_key = load_required_json("vectors/keys/nip06-account-0-leader.json", errors)
    if nip06_key is not None:
        if nip06_key.get("source") != "nostr-protocol/nips 06.md test vector":
            errors.append("vectors/keys/nip06-account-0-leader.json: source mismatch")
        if nip06_key.get("path") != "m/44'/1237'/0'/0/0":
            errors.append("vectors/keys/nip06-account-0-leader.json: path mismatch")
        if nip06_key.get("account") != 0:
            errors.append("vectors/keys/nip06-account-0-leader.json: account mismatch")
        if xonly_pubkey_from_secret(nip06_key.get("secret_key", "")) != nip06_key.get("public_key"):
            errors.append("vectors/keys/nip06-account-0-leader.json: public_key mismatch")
    if public_key_response is not None:
        response_public_key = public_key_response.get("result", {}).get("public_key")
        if response_public_key != key.get("public_key"):
            errors.append("examples/response-get-public-key.json: public_key must match test-key-1")

    for rel in ("kind-1-basic", "kind-1-tags"):
        vector = load_json(f"vectors/events/{rel}.json")
        event = vector["signed_event"]
        computed_serialization = canonical_event_serialization(event)
        computed_id = event_id(event)
        if vector["canonical_serialization"] != computed_serialization:
            errors.append(f"vectors/events/{rel}.json: canonical serialization mismatch")
        if vector["event_id"] != computed_id:
            errors.append(f"vectors/events/{rel}.json: vector event_id mismatch")
        if event["id"] != computed_id:
            errors.append(f"vectors/events/{rel}.json: signed event id mismatch")
        if not verify_schnorr(event["pubkey"], event["id"], event["sig"]):
            errors.append(f"vectors/events/{rel}.json: Schnorr signature verification failed")
        request = load_json(f"examples/request-{rel}.json")
        response = load_json(f"examples/response-{rel}.json")
        if request != vector["request"]:
            errors.append(f"examples/request-{rel}.json: does not match vector request")
        if response != vector["response"]:
            errors.append(f"examples/response-{rel}.json: does not match vector response")

    for rel in review_vector_names():
        check_review_vector(rel, errors)

    for rel in review_screen_vector_names():
        check_review_screen_vector(rel, errors)

    for rel in review_display_frame_vector_names():
        check_review_display_frame_vector(rel, errors)

    for rel in review_detail_page_vector_names():
        check_review_detail_page_vector(rel, errors)

    for rel in review_transcript_vector_names():
        check_review_transcript_vector(rel, errors)

    for rel in nip46_vector_names():
        check_nip46_vector(rel, errors)

    for rel in nip46_policy_file_vector_names():
        check_nip46_policy_file_vector(rel, errors)

    for rel in seedqr_vector_names():
        check_seedqr_vector(rel, errors)

    for rel in account_descriptor_vector_names():
        check_account_descriptor_vector(rel, errors)

    for rel in policy_profile_vector_names():
        check_policy_profile_vector(rel, errors)

    for rel in grant_descriptor_vector_names():
        check_grant_descriptor_vector(rel, errors)

    for rel in policy_decision_vector_names():
        check_policy_decision_vector(rel, errors)

    for rel in route_selection_vector_names():
        check_route_selection_vector(rel, errors)

    for rel in feature_matrix_vector_names():
        check_feature_matrix_vector(rel, errors)

    for rel in smartcard_apdu_vector_names():
        check_smartcard_apdu_vector(rel, errors)

    for rel in invalid_vector_names():
        check_invalid_vector(rel, errors)

    qr_request = load_json("examples/request-kind-1-basic.json")
    qr_vector = load_required_json("vectors/transports/qr-envelope-kind-1-basic.json", errors)
    if qr_vector is not None:
        expected_qr = f"{QR_PREFIX}{base64url_json(qr_request)}"
        if qr_vector.get("envelope") != expected_qr:
            errors.append("vectors/transports/qr-envelope-kind-1-basic.json: envelope mismatch")
        if qr_vector.get("decoded") != qr_request:
            errors.append("vectors/transports/qr-envelope-kind-1-basic.json: decoded request mismatch")
    check_animated_qr_vector("qr-animated-response-kind-1-basic", errors)

    serial_vector = load_required_json("vectors/transports/serial-frame-request-kind-1-basic.json", errors)
    if serial_vector is not None:
        payload = serial_vector.get("payload_base64url", "")
        frame_type = serial_vector.get("type", "")
        expected_serial = (
            f"{SERIAL_PREFIX}{frame_type}:{payload}:{serial_checksum(frame_type, payload)}\n"
        )
        if frame_type not in {"request", "response", "error"}:
            errors.append("vectors/transports/serial-frame-request-kind-1-basic.json: unsupported frame type")
        if not isinstance(payload, str) or not B64URL_RE.fullmatch(payload):
            errors.append("vectors/transports/serial-frame-request-kind-1-basic.json: invalid base64url payload")
        if serial_vector.get("decoded") != qr_request:
            errors.append("vectors/transports/serial-frame-request-kind-1-basic.json: decoded request mismatch")
        if serial_vector.get("frame") != expected_serial:
            errors.append("vectors/transports/serial-frame-request-kind-1-basic.json: frame mismatch")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print("nSealr specs v0 verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
