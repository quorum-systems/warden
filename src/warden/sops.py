"""SOPS file access. Plaintext only ever lives in this process and in sops' pipes; nothing is written decrypted."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import yaml


def decrypt(path: Path) -> dict[str, Any]:
    out = subprocess.run(["sops", "decrypt", str(path)], check=True, capture_output=True).stdout
    doc = yaml.safe_load(out)
    if not isinstance(doc, dict):
        raise ValueError(f"{path} doesn't decrypt to a mapping")
    return doc


PROBE = "probe_not_a_token"


def check_rule(path: Path) -> None:
    """Refuse to write unless the repo's creation rule for `path` encrypts `token` and `previous`.

    The generic gitops/secrets rule encrypts only data/stringData, which would leave tokens in the clear in a file
    that still looks encrypted (its MAC is `ENC[...]`). This encrypts a probe to stdout; nothing touches disk.
    """
    probe = {
        "service": "x",
        "grants": "x:read",
        "keys": [{"name": "x", "token": PROBE, "previous": PROBE, "grants": "*"}],
    }
    out = yaml.safe_load(_encrypt(path, probe))
    item = out["keys"][0]
    if not all(str(item[f]).startswith("ENC[") for f in ("token", "previous")):
        raise ValueError(
            f"the .sops.yaml rule matching {path} doesn't encrypt `token`; add the service-keys rule above the "
            "generic gitops/secrets rule (first match wins)"
        )


def _encrypt(path: Path, doc: dict[str, Any]) -> bytes:
    return subprocess.run(
        [
            "sops",
            "encrypt",
            "--filename-override",
            str(path.resolve()),
            "--input-type",
            "yaml",
            "--output-type",
            "yaml",
            "/dev/stdin",
        ],
        input=yaml.safe_dump(doc, sort_keys=False).encode(),
        check=True,
        capture_output=True,
        cwd=path.resolve().parent,
    ).stdout


def set_item(path: Path, index: int, value: dict[str, Any]) -> None:
    """Set `keys[index]` (index == len appends) through `sops set`, value on stdin so tokens never reach argv."""
    check_rule(path)
    subprocess.run(
        ["sops", "set", "--value-stdin", str(path.resolve()), f'["keys"][{index}]'],
        input=json.dumps(value).encode(),
        check=True,
        capture_output=True,
        cwd=path.resolve().parent,
    )


def set_field(path: Path, key: str, value: str) -> None:
    """Set a top-level string field (not a token)."""
    subprocess.run(
        ["sops", "set", "--value-stdin", str(path.resolve()), f'["{key}"]'],
        input=json.dumps(value).encode(),
        check=True,
        capture_output=True,
        cwd=path.resolve().parent,
    )


def unset_item(path: Path, index: int) -> None:
    subprocess.run(
        ["sops", "unset", str(path.resolve()), f'["keys"][{index}]'],
        check=True,
        capture_output=True,
        cwd=path.resolve().parent,
    )


def create(path: Path, doc: dict[str, Any]) -> None:
    """Encrypt a new file with the repo's creation rules for `path` (found from the file's directory)."""
    check_rule(path)
    path.write_bytes(_encrypt(path, doc))
