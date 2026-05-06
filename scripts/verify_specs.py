#!/usr/bin/env python3
"""Verify NostrSeal M1 specs, examples, and cryptographic fixtures."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import secp256k1


ROOT = Path(__file__).resolve().parents[1]
HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{128}$")


def load_json(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


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
    if method not in {"get_public_key", "sign_event"}:
        errors.append(f"{path}: unsupported method {method!r}")
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

    key = load_json("vectors/keys/test-key-1.json")
    if not HEX32_RE.fullmatch(key.get("public_key", "")):
        errors.append("vectors/keys/test-key-1.json: invalid public_key")

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

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print("NostrSeal specs v0 verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
