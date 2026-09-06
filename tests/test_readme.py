"""The README example must keep working.

A redaction library whose documented output is wrong is worse than one with no
documentation, because the wrong output is what a reader will trust. This executes the
quickstart and compares it against the result the README claims, so the two cannot drift.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

README = Path(__file__).resolve().parents[1] / "README.md"


def _blocks(language: str) -> list[str]:
    return re.findall(rf"```{language}\n(.*?)```", README.read_text(encoding="utf-8"), re.S)


@pytest.mark.skipif(not README.exists(), reason="README is not present in this install")
class TestQuickstart:
    def _run(self) -> str:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, our own source
            [sys.executable, "-c", _blocks("python")[0]],
            capture_output=True,
            text=True,
            check=True,
            env={
                "TRACESHIELD_HASH_SECRET": "readme-example-salt-not-a-secret",
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": str(README.parent / "src"),
            },
        )
        return completed.stdout

    def test_output_matches_the_documented_json(self) -> None:
        produced, _ = json.JSONDecoder().raw_decode(self._run())
        assert produced == json.loads(_blocks("json")[0])

    def test_output_matches_the_documented_findings(self) -> None:
        stdout = self._run()
        _, end = json.JSONDecoder().raw_decode(stdout)
        assert stdout[end:].strip().splitlines() == _blocks("text")[0].strip().splitlines()
