#!/usr/bin/env python3
"""Capture sanitized public Hub read traffic from the pinned official client."""

from __future__ import annotations

import argparse
import base64
import importlib.metadata
import json
import platform
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx
from huggingface_hub import HfApi, get_hf_file_metadata, hf_hub_url, set_client_factory
from huggingface_hub.utils import build_hf_headers
from huggingface_hub.utils._http import get_session, hf_request_event_hook


CAPTURED_REQUEST_HEADERS = {
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "range",
    "user-agent",
}
CAPTURED_RESPONSE_HEADERS = {
    "accept-ranges",
    "content-length",
    "content-range",
    "content-type",
    "etag",
    "link",
    "location",
    "x-linked-etag",
    "x-linked-size",
    "x-repo-commit",
    "x-xet-hash",
    "x-xet-refresh-route",
}
MAX_BODY_BYTES = 128 << 10


def selected_headers(headers: httpx.Headers, names: set[str]) -> dict[str, str]:
    selected: dict[str, str] = {}
    for name, value in headers.multi_items():
        lower = name.lower()
        if lower not in names:
            continue
        if lower == "authorization":
            value = "Bearer <redacted>"
        if lower in {"link", "location"} and any(
            marker in value.lower()
            for marker in ("signature=", "policy=", "key-pair-id=", "x-amz-signature=", "x-goog-signature=")
        ):
            parsed = urlsplit(value)
            value = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "<redacted-signed-query>", ""))
        if lower in selected:
            selected[lower] += ", " + value
        else:
            selected[lower] = value
    return selected


def sanitized_json(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: "<redacted>" if key.lower() in {"accesstoken", "token"} else sanitized_json(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitized_json(item) for item in value]
    return value


class Capture:
    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.host = urlsplit(self.endpoint).netloc
        self.operation = ""
        self.records: list[dict[str, object]] = []
        self.lock = threading.Lock()

    def set_operation(self, operation: str) -> None:
        with self.lock:
            self.operation = operation

    def response(self, response: httpx.Response) -> None:
        request = response.request
        if request.url.host != self.host:
            return
        response.read()
        body: object | None = None
        if response.content and len(response.content) <= MAX_BODY_BYTES:
            content_type = response.headers.get("content-type", "").lower()
            if "json" in content_type:
                try:
                    body = sanitized_json(response.json())
                except ValueError:
                    body = {"base64": base64.b64encode(response.content).decode("ascii")}
            elif content_type.startswith("text/"):
                body = {"text": response.text}
            else:
                body = {"base64": base64.b64encode(response.content).decode("ascii")}
        with self.lock:
            self.records.append(
                {
                    "operation": self.operation,
                    "request": {
                        "method": request.method,
                        "path": request.url.raw_path.decode("ascii"),
                        "headers": selected_headers(request.headers, CAPTURED_REQUEST_HEADERS),
                    },
                    "response": {
                        "status": response.status_code,
                        "headers": selected_headers(response.headers, CAPTURED_RESPONSE_HEADERS),
                        **({"body": body} if body is not None else {}),
                    },
                }
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default="https://huggingface.co")
    parser.add_argument("--repo", default="hf-internal-testing/tiny-random-bert")
    parser.add_argument("--ordinary-file", default="config.json")
    parser.add_argument("--xet-file", default="pytorch_model.bin")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    capture = Capture(args.endpoint)
    set_client_factory(
        lambda: httpx.Client(
            event_hooks={"request": [hf_request_event_hook], "response": [capture.response]},
            follow_redirects=True,
            timeout=30,
        )
    )
    api = HfApi(endpoint=args.endpoint, token=False)

    capture.set_operation("model-info-main")
    info = api.model_info(args.repo, files_metadata=True)
    if not info.sha:
        raise RuntimeError("model info did not include a commit OID")
    revision = info.sha

    capture.set_operation("model-info-immutable")
    api.model_info(args.repo, revision=revision, files_metadata=True)

    capture.set_operation("tree-recursive")
    list(api.list_repo_tree(args.repo, revision=revision, recursive=True, expand=False))

    capture.set_operation("head-ordinary")
    ordinary = get_hf_file_metadata(
        hf_hub_url(args.repo, args.ordinary_file, revision=revision, endpoint=args.endpoint), token=False
    )
    if ordinary.commit_hash != revision or ordinary.xet_file_data is not None:
        raise RuntimeError("ordinary fixture metadata changed")

    capture.set_operation("head-xet")
    xet = get_hf_file_metadata(
        hf_hub_url(args.repo, args.xet_file, revision=revision, endpoint=args.endpoint), token=False
    )
    if xet.commit_hash != revision or xet.xet_file_data is None:
        raise RuntimeError("Xet fixture metadata changed")

    capture.set_operation("xet-read-token")
    token_response = get_session().get(xet.xet_file_data.refresh_route, headers=build_hf_headers(token=False))
    token_response.raise_for_status()

    capture.set_operation("get-ordinary-range")
    ordinary_response = get_session().get(
        hf_hub_url(args.repo, args.ordinary_file, revision=revision, endpoint=args.endpoint),
        headers={**build_hf_headers(token=False), "Range": "bytes=1-17"},
    )
    ordinary_response.raise_for_status()
    if ordinary_response.content != b'\n  "attention_pro':
        raise RuntimeError("ordinary range fixture changed")

    document = {
        "schema": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "endpoint": args.endpoint,
        "repo": args.repo,
        "revision": revision,
        "ordinary_file": args.ordinary_file,
        "xet_file": args.xet_file,
        "runtime": {
            "python": platform.python_version(),
            "huggingface_hub": importlib.metadata.version("huggingface_hub"),
            "hf_xet": importlib.metadata.version("hf_xet"),
            "httpx": importlib.metadata.version("httpx"),
        },
        "records": capture.records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
