#!/usr/bin/env python3
"""Exercise an xet-go Hub read endpoint with the pinned official client."""

from __future__ import annotations

import argparse
import os
from importlib.metadata import version

import httpx
from huggingface_hub import HfApi, get_hf_file_metadata, hf_hub_url, snapshot_download
from huggingface_hub.errors import RemoteEntryNotFoundError, RepositoryNotFoundError, RevisionNotFoundError


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--snapshot-dir")
    args = parser.parse_args()

    assert version("huggingface_hub") == "1.27.0"
    assert version("hf_xet") == "1.6.0"

    repo = "owner/model"
    oid = "1111111111111111111111111111111111111111"
    api = HfApi(endpoint=args.endpoint, token=args.token)

    info = api.model_info(repo, files_metadata=True)
    assert info.id == repo and info.sha == oid
    assert [sibling.rfilename for sibling in info.siblings] == ["config.json", "weights/model.bin"]
    assert info.siblings[0].blob_id.startswith("xet-go:file:sha256:")

    feature = api.model_info(repo, revision="feature/test", files_metadata=True)
    assert feature.sha == oid

    tree = list(api.list_repo_tree(repo, revision="main", recursive=True, expand=False))
    files = {item.path: item for item in tree if item.__class__.__name__ == "RepoFile"}
    assert files["config.json"].xet_hash is None
    assert len(files["weights/model.bin"].xet_hash) == 64

    ordinary = get_hf_file_metadata(
        hf_hub_url(repo, "config.json", revision="main", endpoint=args.endpoint), token=args.token
    )
    assert ordinary.commit_hash == oid and ordinary.size == 22 and ordinary.xet_file_data is None

    xet = get_hf_file_metadata(
        hf_hub_url(repo, "weights/model.bin", revision="main", endpoint=args.endpoint), token=args.token
    )
    assert xet.commit_hash == oid and xet.size == 1400 and xet.xet_file_data is not None
    assert xet.xet_file_data.refresh_route.startswith(args.endpoint + "/api/models/")

    headers = {"Authorization": f"Bearer {args.token}"}
    token = httpx.get(xet.xet_file_data.refresh_route, headers=headers).raise_for_status().json()
    assert set(token) == {"accessToken", "casUrl", "exp"}
    assert token["accessToken"] and isinstance(token["exp"], int)

    ranged = httpx.get(
        hf_hub_url(repo, "config.json", revision="main", endpoint=args.endpoint),
        headers={**headers, "Range": "bytes=1-4"},
    )
    assert ranged.status_code == 206 and ranged.content == b'"mod'

    try:
        get_hf_file_metadata(
            hf_hub_url(repo, "missing.json", revision="main", endpoint=args.endpoint), token=args.token
        )
    except RemoteEntryNotFoundError:
        pass
    else:
        raise AssertionError("missing file was not classified as RemoteEntryNotFoundError")

    try:
        api.model_info(repo, revision="missing")
    except RevisionNotFoundError:
        pass
    else:
        raise AssertionError("missing revision was not classified as RevisionNotFoundError")

    try:
        api.model_info("owner/missing")
    except RepositoryNotFoundError:
        pass
    else:
        raise AssertionError("denied repository was not classified as RepositoryNotFoundError")

    if args.snapshot_dir:
        snapshot = snapshot_download(
            repo_id=repo,
            revision="main",
            endpoint=args.endpoint,
            token=args.token,
            local_dir=args.snapshot_dir,
            cache_dir=os.path.join(args.snapshot_dir, ".hf-cache"),
            force_download=True,
            max_workers=2,
        )
        with open(os.path.join(snapshot, "config.json"), "rb") as downloaded:
            assert downloaded.read() == b'{"model_type":"bert"}\n'
        with open(os.path.join(snapshot, "weights", "model.bin"), "rb") as downloaded:
            assert downloaded.read() == b"xet-model-data" * 100

    print("official Hub read compatibility passed")


if __name__ == "__main__":
    main()
