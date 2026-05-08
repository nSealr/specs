#!/usr/bin/env python3
"""Verify NostrSeal M1 specs, examples, and cryptographic fixtures."""

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
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
QR_PREFIX = "nseal1:"
SERIAL_PREFIX = "nseal1f:"
APDU_HEX_RE = re.compile(r"^[0-9a-f]+$")
LIMIT_PROFILE = "vectors/limits/nseal-v0.json"


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
    if profile.get("format") != "nostrseal-implementation-limits-v0":
        errors.append(f"{LIMIT_PROFILE}: format mismatch")
    if profile.get("name") != "nostrseal-v0":
        errors.append(f"{LIMIT_PROFILE}: name mismatch")
    limits = profile.get("limits")
    if not isinstance(limits, dict):
        errors.append(f"{LIMIT_PROFILE}: limits must be an object")
        return
    required = {
        "max_request_id_length",
        "max_decoded_request_json_bytes",
        "max_static_qr_decoded_json_bytes",
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
    if method not in {"get_capabilities", "get_public_key", "sign_event"}:
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


def expected_review(template: dict) -> dict:
    kind_names = {
        0: "Metadata",
        1: "Short Text Note",
        3: "Contacts",
        6: "Repost",
        7: "Reaction",
        9735: "Zap Receipt",
    }
    content = template["content"]
    tags = template["tags"]
    tag_summary = []
    for tag in tags:
        if not tag:
            continue
        name = tag[0]
        value = tag[1] if len(tag) > 1 else ""
        if len(value) > 8 and name in {"p", "e"}:
            value = f"{value[:8]}..."
        tag_summary.append(f"{name}: {value}" if value else name)
    warnings = []
    if template["kind"] not in kind_names:
        warnings.append("Unknown event kind.")
    if len(content) > 280:
        warnings.append("Long content.")
    if not content:
        warnings.append("Empty content.")
    if any(tag and tag[0] == "p" for tag in tags):
        warnings.append("Event includes pubkey mentions.")
    if any(tag and tag[0] == "e" for tag in tags):
        warnings.append("Event references other events.")
    if len(tags) > 8:
        warnings.append("Many tags.")
    return {
        "kind": template["kind"],
        "kind_name": kind_names.get(template["kind"], "Unknown"),
        "created_at": template["created_at"],
        "content_preview": content if len(content) <= 120 else f"{content[:120]}...",
        "content_length": len(content),
        "tag_count": len(tags),
        "tag_summary": tag_summary,
        "warnings": warnings,
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
    pages = [
        {
            "title": "Event",
            "lines": [
                f"Kind {review['kind']}",
                str(review["kind_name"]),
                f"Created {review['created_at']}",
            ],
            "action": "next",
        },
        {
            "title": "Content",
            "lines": [str(review["content_preview"])],
            "action": "next",
        },
        {
            "title": "Tags",
            "lines": expected_tag_page_lines(review),
            "action": "next",
        },
    ]
    if review["warnings"]:
        pages.append(
            {
                "title": "Warnings",
                "lines": [str(warning) for warning in review["warnings"]],
                "action": "approve_or_reject",
            }
        )
    else:
        pages.append(
            {
                "title": "Decision",
                "lines": ["Approve signing only if all pages match."],
                "action": "approve_or_reject",
            }
        )
    return pages


def expected_tag_page_lines(review: dict) -> list[str]:
    tag_count = review["tag_count"]
    if tag_count == 0:
        return ["No tags"]
    label = "1 tag" if tag_count == 1 else f"{tag_count} tags"
    return [label, *[str(item) for item in review["tag_summary"]]]


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


def review_transcript_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "review-transcripts").glob("*.json"))


def nip46_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "nip46").glob("*.json"))


def nip46_policy_file_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "nip46-policy-files").glob("*.json"))


def invalid_vector_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "vectors" / "invalid").glob("*.json"))


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

    screen_review_name = vector.get("screen_review_vector")
    if not isinstance(screen_review_name, str):
        errors.append(f"vectors/review-transcripts/{rel}.json: screen_review_vector must be a string")
        return
    screen_vector = load_required_json(f"vectors/review-screens/{screen_review_name}.json", errors)
    if screen_vector is None:
        return

    request = vector.get("request")
    if not isinstance(request, dict):
        errors.append(f"vectors/review-transcripts/{rel}.json: request must be an object")
        return
    check_request_shape(Path(f"vectors/review-transcripts/{rel}.json"), request, errors)
    if request != source_vector.get("decoded"):
        errors.append(f"vectors/review-transcripts/{rel}.json: request must match source QR vector")
    if request != screen_vector.get("request"):
        errors.append(f"vectors/review-transcripts/{rel}.json: request must match review-screen vector")
    if vector.get("qr_envelope") != source_vector.get("envelope"):
        errors.append(f"vectors/review-transcripts/{rel}.json: qr_envelope mismatch")
    if vector.get("approval_digest") != screen_vector.get("screen_review", {}).get("approval_digest"):
        errors.append(f"vectors/review-transcripts/{rel}.json: approval_digest mismatch")

    buttons = vector.get("buttons")
    if not isinstance(buttons, list) or not all(isinstance(button, str) for button in buttons):
        errors.append(f"vectors/review-transcripts/{rel}.json: buttons must be a string list")
        return
    expected = expected_review_transcript(screen_vector["screen_review"], buttons, errors, rel)
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
        errors.append(f"{vector_path}: QR envelope requires nseal1 prefix")
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


def check_serial_frame_payload(vector_path: str, frame: object, errors: list[str]) -> None:
    limits = implementation_limit_values()
    if not isinstance(frame, str):
        errors.append(f"{vector_path}: serial frame must be a string")
        return
    if utf8_size(frame) > limits["max_serial_frame_bytes"]:
        errors.append(f"{vector_path}: serial frame exceeds max_serial_frame_bytes")
    if not frame.startswith(SERIAL_PREFIX):
        errors.append(f"{vector_path}: serial frame requires nseal1f prefix")
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
        errors.append(f"{vector_path}: serial frame type is unsupported")
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
    elif category == "nip46":
        check_invalid_nip46_payload(vector_path, vector, rejection_errors)
    elif category == "nip46-policy-file":
        policy = vector.get("policy_file")
        if not isinstance(policy, dict):
            rejection_errors.append(f"{vector_path}: policy_file must be an object")
        else:
            if policy.get("format") != "nseal-nip46-policy-v0":
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
    for forbidden in ("nostrseal_request", "nostrseal_response", "response_message", "local_response_message"):
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


def expected_nostrseal_request_from_nip46_message(
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
    errors.append(f"{vector_path}: cannot create NostrSeal request for NIP-46 method")
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

    nostrseal_request = expected_nostrseal_request_from_nip46_message(vector_path, message, errors)
    if nostrseal_request is None:
        return None
    return {
        "type": "signer_request",
        "permission_requirement": requirement,
        "nostrseal_request": nostrseal_request,
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
    if vector.get("format") != "nseal-nip46-policy-v0":
        errors.append(f"{vector_path}: format mismatch")
    approved_permissions = vector.get("approved_permissions")
    if not isinstance(approved_permissions, list):
        errors.append(f"{vector_path}: approved_permissions must be a list")
        return
    for index, permission in enumerate(approved_permissions):
        normalized = normalized_nip46_permission(vector_path, permission, errors)
        if normalized is not None and permission != normalized:
            errors.append(f"{vector_path}: approved_permissions[{index}] must be normalized")


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
        if "nostrseal_request" in vector or "nostrseal_response" in vector:
            errors.append(f"{vector_path}: ping must not include NostrSeal request/response")
        if vector.get("local_response_message") != {"id": request_id, "result": "pong"}:
            errors.append(f"{vector_path}: local_response_message mismatch")
        check_nip46_permission_policy(vector_path, vector, {"method": "ping"}, errors)
        return

    if method == "connect":
        check_nip46_connect_intent(vector_path, vector, message, errors)
        return

    nostrseal_request = vector.get("nostrseal_request")
    if not isinstance(nostrseal_request, dict):
        errors.append(f"{vector_path}: nostrseal_request must be an object")
        return
    check_request_shape(Path(vector_path), nostrseal_request, errors)
    if nostrseal_request.get("request_id") != request_id:
        errors.append(f"{vector_path}: nostrseal_request request_id mismatch")
    if nostrseal_request.get("method") != method:
        errors.append(f"{vector_path}: nostrseal_request method mismatch")

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
                if event_template != nostrseal_request.get("params", {}).get("event_template"):
                    errors.append(f"{vector_path}: sign_event param must match NostrSeal event_template")
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

    nostrseal_response = vector.get("nostrseal_response")
    if not isinstance(nostrseal_response, dict):
        errors.append(f"{vector_path}: nostrseal_response must be an object")
        return
    check_response_shape(Path(vector_path), nostrseal_response, errors)
    if nostrseal_response.get("request_id") != request_id:
        errors.append(f"{vector_path}: nostrseal_response request_id mismatch")

    response_message = check_nip46_response_message(vector_path, vector.get("response_message"), request_id, errors)
    if response_message is None:
        return
    if nostrseal_response.get("ok") is False:
        error = nostrseal_response.get("error", {})
        if response_message.get("error") != f"{error.get('code')}: {error.get('message')}":
            errors.append(f"{vector_path}: response_message error mismatch")
        return

    result = nostrseal_response.get("result", {})
    if method == "get_public_key":
        if response_message.get("result") != result.get("public_key"):
            errors.append(f"{vector_path}: public-key result mismatch")
    if method == "sign_event":
        if response_message.get("result") != compact_json(result.get("event")):
            errors.append(f"{vector_path}: signed-event result mismatch")


def main() -> int:
    errors: list[str] = []

    for schema in (
        "signing-request-v0.schema.json",
        "signing-response-v0.schema.json",
        "error-v0.schema.json",
        "nip46-policy-file-v0.schema.json",
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

    for rel in review_transcript_vector_names():
        check_review_transcript_vector(rel, errors)

    for rel in nip46_vector_names():
        check_nip46_vector(rel, errors)

    for rel in nip46_policy_file_vector_names():
        check_nip46_policy_file_vector(rel, errors)

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
