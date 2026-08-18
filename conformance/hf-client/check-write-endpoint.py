#!/usr/bin/env python3
"""Exercise the pinned Hub write surface without client-global workarounds."""

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
from importlib.metadata import version
from pathlib import Path

from huggingface_hub import HfApi, ModelHubMixin, hf_hub_download


class FixtureModel(ModelHubMixin):
    def __init__(self, body: bytes) -> None:
        self.body = body

    def _save_pretrained(self, save_directory: Path) -> None:
        with open(save_directory / "pushed.bin", "wb") as file:
            file.write(self.body)

    def generate_model_card(self, **kwargs):
        class Card:
            @staticmethod
            def save(path: Path) -> None:
                path.write_text("---\n---\n", encoding="utf-8")

        return Card()

    @classmethod
    def _from_pretrained(cls, **kwargs):  # pragma: no cover - write conformance only
        raise NotImplementedError


def assert_download(args: argparse.Namespace, path: str, expected: bytes) -> None:
    downloaded = hf_hub_download(
        repo_id="owner/model",
        filename=path,
        endpoint=args.endpoint,
        token=args.token,
        local_dir=args.download_dir,
        force_download=True,
    )
    with open(downloaded, "rb") as file:
        actual = file.read()
    if hashlib.sha256(actual).digest() != hashlib.sha256(expected).digest() or actual != expected:
        raise AssertionError(f"downloaded upload is not byte-identical: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--download-dir", required=True)
    args = parser.parse_args()

    assert version("huggingface_hub") == "1.27.0"
    assert version("hf_xet") == "1.6.0"

    api = HfApi(endpoint=args.endpoint, token=args.token)
    identity = api.whoami()
    if identity.get("name") != "user:python":
        raise AssertionError(f"unexpected identity: {identity!r}")

    # create_repo handles a normal 409 itself when exist_ok is true.
    api.create_repo("owner/model", exist_ok=True)

    # Exercise the process-global Xet client state in the required direction:
    # establish a download transport first, then use that same process to
    # negotiate and perform a write.
    initial_download = hf_hub_download(
        repo_id="owner/model",
        filename="weights/model.bin",
        endpoint=args.endpoint,
        token=args.token,
        local_dir=args.download_dir,
        force_download=True,
    )
    if os.path.getsize(initial_download) == 0:
        raise AssertionError("initial Xet download was empty")

    expected = (b"official-client-xet-write\x00" * 100_000) + os.urandom(31)
    with tempfile.NamedTemporaryFile() as source:
        source.write(expected)
        source.flush()
        commit = api.upload_file(
            path_or_fileobj=source.name,
            path_in_repo="uploaded/model.bin",
            repo_id="owner/model",
            commit_message="official client Xet upload",
        )
    if not commit.oid:
        raise AssertionError(f"missing commit OID: {commit!r}")
    assert_download(args, "uploaded/model.bin", expected)

    folder_regular = b'{"source":"official upload_folder"}\n'
    folder_large = (b"official-client-folder-write\x00" * 60_000) + os.urandom(17)
    with tempfile.TemporaryDirectory() as folder:
        os.makedirs(os.path.join(folder, "nested"))
        with open(os.path.join(folder, "nested", "config.json"), "wb") as file:
            file.write(folder_regular)
        with open(os.path.join(folder, "weights.bin"), "wb") as file:
            file.write(folder_large)
        folder_commit = api.upload_folder(
            folder_path=folder,
            path_in_repo="folder",
            repo_id="owner/model",
            commit_message="official client folder upload",
        )
    if not folder_commit.oid:
        raise AssertionError(f"missing folder commit OID: {folder_commit!r}")
    assert_download(args, "folder/nested/config.json", folder_regular)
    assert_download(args, "folder/weights.bin", folder_large)
    unchanged = api.upload_file(
        path_or_fileobj=folder_regular,
        path_in_repo="folder/nested/config.json",
        repo_id="owner/model",
        commit_message="unchanged regular file must be a no-op",
    )
    if unchanged.oid != folder_commit.oid:
        raise AssertionError(f"unchanged regular file created a commit: {unchanged!r}")

    pushed_body = (b"official-push-to-hub-write\x00" * 60_000) + os.urandom(23)
    pushed_url = FixtureModel(pushed_body).push_to_hub(
        "owner/model",
        token=args.token,
        commit_message="official push_to_hub upload",
        allow_patterns=["pushed.bin"],
    )
    if "/commit/" not in pushed_url:
        raise AssertionError(f"push_to_hub returned an invalid commit URL: {pushed_url!r}")
    assert_download(args, "pushed.bin", pushed_body)

    cli_body = (b"official-hf-cli-write\x00" * 60_000) + os.urandom(19)
    with tempfile.NamedTemporaryFile() as source:
        source.write(cli_body)
        source.flush()
        environment = os.environ.copy()
        environment["HF_ENDPOINT"] = args.endpoint
        environment["HF_TOKEN"] = args.token
        executable = str(Path(sys.executable).with_name("hf"))
        completed = subprocess.run(
            [
                executable,
                "upload",
                "owner/model",
                source.name,
                "uploaded/cli.bin",
                "--token",
                args.token,
                "--quiet",
            ],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
    if not completed.stdout.strip():
        raise AssertionError(f"hf upload returned no commit identifier: {completed.stderr!r}")
    assert_download(args, "uploaded/cli.bin", cli_body)

    print("official Hub write compatibility passed")


if __name__ == "__main__":
    main()
