#!/usr/bin/env python3
"""Verify NostrSeal M1 specs, examples, and cryptographic fixtures."""

from __future__ import annotations

import hashlib
import json
import re
import base64
from pathlib import Path

import secp256k1


ROOT = Path(__file__).resolve().parents[1]
HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{128}$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
QR_PREFIX = "nseal1:"
SERIAL_PREFIX = "nseal1f:"
APDU_HEX_RE = re.compile(r"^[0-9a-f]+$")


def load_json(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def load_required_json(rel: str, errors: list[str]) -> dict | None:
    path = ROOT / rel
    if not path.exists():
        errors.append(f"{rel}: missing required file")
        return None
    return json.loads(path.read_text(encoding="utf-8"))


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


def check_request_shape(path: Path, value: dict, errors: list[str]) -> None:
    if value.get("version") != 1:
        errors.append(f"{path}: version must be 1")
    if not isinstance(value.get("request_id"), str) or not value["request_id"]:
        errors.append(f"{path}: request_id must be a non-empty string")
    method = value.get("method")
    if method not in {"get_capabilities", "get_public_key", "sign_event"}:
        errors.append(f"{path}: unsupported method {method!r}")
    if method == "get_capabilities" and "params" in value:
        errors.append(f"{path}: get_capabilities must not include params in v0")
    if method == "get_public_key" and "params" in value:
        errors.append(f"{path}: get_public_key must not include params in v0")
    if method == "sign_event":
        template = value.get("params", {}).get("event_template")
        if not isinstance(template, dict):
            errors.append(f"{path}: sign_event requires params.event_template")
            return
        forbidden = {"id", "pubkey", "sig"} & set(template)
        if forbidden:
            errors.append(f"{path}: event_template contains forbidden fields: {sorted(forbidden)}")
        for field in ("created_at", "kind", "tags", "content"):
            if field not in template:
                errors.append(f"{path}: event_template missing {field}")


def request_shape_errors(path: Path, value: dict) -> list[str]:
    errors: list[str] = []
    check_request_shape(path, value, errors)
    return errors


def check_response_shape(path: Path, value: dict, errors: list[str]) -> None:
    if value.get("version") != 1:
        errors.append(f"{path}: version must be 1")
    if not isinstance(value.get("request_id"), str) or not value["request_id"]:
        errors.append(f"{path}: request_id must be a non-empty string")
    if value.get("ok") is True:
        result = value.get("result")
        if not isinstance(result, dict):
            errors.append(f"{path}: successful response requires result")
            return
        if "public_key" in result and not HEX32_RE.fullmatch(result["public_key"]):
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
        if "event" in result:
            event = result["event"]
            for field in ("id", "pubkey", "created_at", "kind", "tags", "content", "sig"):
                if field not in event:
                    errors.append(f"{path}: signed event missing {field}")
            if "id" in event and not HEX32_RE.fullmatch(event["id"]):
                errors.append(f"{path}: event id must be 32-byte lowercase hex")
            if "pubkey" in event and not HEX32_RE.fullmatch(event["pubkey"]):
                errors.append(f"{path}: pubkey must be 32-byte lowercase hex")
            if "sig" in event and not HEX64_RE.fullmatch(event["sig"]):
                errors.append(f"{path}: signature must be 64-byte lowercase hex")
    elif value.get("ok") is False:
        error = value.get("error")
        if not isinstance(error, dict):
            errors.append(f"{path}: error response requires error object")
            return
        for field in ("code", "message", "retryable"):
            if field not in error:
                errors.append(f"{path}: error missing {field}")
    else:
        errors.append(f"{path}: ok must be true or false")


def main() -> int:
    errors: list[str] = []

    for schema in ("signing-request-v0.schema.json", "signing-response-v0.schema.json", "error-v0.schema.json"):
        load_json(f"schemas/{schema}")

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
    if capability_vector is not None and capability_request is not None and capability_response is not None:
        if capability_vector.get("request") != capability_request:
            errors.append("vectors/devices/esp32-s3-capabilities-scaffold.json: request mismatch")
        if capability_vector.get("response") != capability_response:
            errors.append("vectors/devices/esp32-s3-capabilities-scaffold.json: response mismatch")
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

    qr_request = load_json("examples/request-kind-1-basic.json")
    qr_vector = load_required_json("vectors/transports/qr-envelope-kind-1-basic.json", errors)
    if qr_vector is not None:
        expected_qr = f"{QR_PREFIX}{base64url_json(qr_request)}"
        if qr_vector.get("envelope") != expected_qr:
            errors.append("vectors/transports/qr-envelope-kind-1-basic.json: envelope mismatch")
        if qr_vector.get("decoded") != qr_request:
            errors.append("vectors/transports/qr-envelope-kind-1-basic.json: decoded request mismatch")

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

    apdu_pubkey = load_required_json("vectors/smartcard/get-public-key.json", errors)
    if apdu_pubkey is not None:
        if apdu_pubkey.get("command_hex") != "80100000":
            errors.append("vectors/smartcard/get-public-key.json: command_hex mismatch")
        expected_response = f"{key['public_key']}9000"
        if apdu_pubkey.get("response_hex") != expected_response:
            errors.append("vectors/smartcard/get-public-key.json: response_hex mismatch")

    apdu_sign = load_required_json("vectors/smartcard/sign-event-id-kind-1-basic.json", errors)
    if apdu_sign is not None:
        expected_command = f"8020000020{load_json('vectors/events/kind-1-basic.json')['event_id']}"
        if apdu_sign.get("command_hex") != expected_command:
            errors.append("vectors/smartcard/sign-event-id-kind-1-basic.json: command_hex mismatch")
        if apdu_sign.get("expected_status_word") != "9000":
            errors.append("vectors/smartcard/sign-event-id-kind-1-basic.json: expected_status_word mismatch")
        if apdu_sign.get("expected_data_length") != 64:
            errors.append("vectors/smartcard/sign-event-id-kind-1-basic.json: expected_data_length must be 64")
        if not APDU_HEX_RE.fullmatch(apdu_sign.get("command_hex", "")):
            errors.append("vectors/smartcard/sign-event-id-kind-1-basic.json: command_hex must be lowercase hex")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print("NostrSeal specs v0 verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
