"""The handoff and the tracker must agree with each other and with the repository.

prompt.txt exists to be pasted into a fresh agent session, which means an agent will act on
it without checking whether it is still true. A stale handoff is therefore not a
documentation problem, it is a correctness problem: it sends the next session to the wrong
task or at a file that no longer exists. These tests make that impossible to miss.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROMPT = ROOT / "prompt.txt"
TRACKER = ROOT / "docs" / "Tracker.md"

pytestmark = pytest.mark.skipif(
    not PROMPT.exists() or not TRACKER.exists(),
    reason="handoff files are not part of an installed distribution",
)

_TASK_HEADING = re.compile(r"^### (TS-\d{3}) — (.+?) · `([A-Z ]+)`$", re.M)
_MAP_ENTRY = re.compile(r"^  ([A-Za-z0-9_.\-/]+/?)\s{2,}\S", re.M)


def _tasks() -> list[tuple[str, str, str]]:
    return _TASK_HEADING.findall(TRACKER.read_text(encoding="utf-8"))


class TestTracker:
    def test_task_ids_are_unique(self) -> None:
        ids = [task_id for task_id, _, _ in _tasks()]
        assert len(set(ids)) == len(ids)

    def test_exactly_one_task_is_next(self) -> None:
        """An agent is told to take the task marked NEXT. Two would make that ambiguous;
        none would send it looking for work to invent."""
        assert [task_id for task_id, _, status in _tasks() if status == "NEXT"].__len__() == 1

    def test_every_status_is_recognised(self) -> None:
        allowed = {"DONE", "IN REVIEW", "NEXT", "PLANNED", "BLOCKED"}
        assert {status for _, _, status in _tasks()} <= allowed

    def test_the_current_position_table_names_the_next_task(self) -> None:
        next_id = next(task_id for task_id, _, status in _tasks() if status == "NEXT")
        position = TRACKER.read_text(encoding="utf-8").split("## Current position", 1)[1]
        assert next_id in position.split("\n---\n", 1)[0]

    def test_relative_links_resolve(self) -> None:
        text = TRACKER.read_text(encoding="utf-8")
        targets = re.findall(r"\]\((?!https?:)([^)#]+)", text)
        missing = [t for t in targets if not (TRACKER.parent / t).exists()]
        assert missing == []


class TestHandoff:
    def test_it_points_at_the_task_the_tracker_marks_next(self) -> None:
        next_id = next(task_id for task_id, _, status in _tasks() if status == "NEXT")
        assert f"YOUR TASK: {next_id}" in PROMPT.read_text(encoding="utf-8")

    def test_every_path_in_the_repository_map_exists(self) -> None:
        section = PROMPT.read_text(encoding="utf-8").split("MAP OF THE REPOSITORY", 1)[1]
        paths = _MAP_ENTRY.findall(section)
        assert paths, "the repository map is empty or its formatting changed"
        assert [path for path in paths if not (ROOT / path).exists()] == []

    def test_it_names_the_correct_identity(self) -> None:
        text = PROMPT.read_text(encoding="utf-8")
        assert "Harsha2803" in text
        assert "cheellasreeharsha2803@gmail.com" in text
        # The employer identities appear only as prohibitions, never as values to use.
        for forbidden in ("harshaJKT", "@jktech.com"):
            for line in text.splitlines():
                if forbidden in line:
                    assert "Never use" in line or "never" in line.lower()

    def test_it_tells_the_agent_where_to_start_and_how_to_finish(self) -> None:
        text = PROMPT.read_text(encoding="utf-8")
        for section in ("DO THIS NOW", "HARD RULES", "CURRENT STATE", "FINISHING"):
            assert section in text

    def test_it_carries_no_secret_of_its_own(self) -> None:
        """Dogfooding. The handoff is pasted into chat windows and read by strangers, so it
        is exactly the kind of document that must not accumulate credentials. Running our own
        engine over it is both a check on the document and a check on the engine: this test
        is what found the path and URL false positives fixed in the entropy detector."""
        from traceshield import Policy, Sanitizer, ValueHasher

        sanitizer = Sanitizer(
            policy=Policy.default(),
            hasher=ValueHasher.from_secret("handoff-scan-salt-not-a-secret"),
        )
        result = sanitizer.sanitize_attribute("handoff.text", PROMPT.read_text(encoding="utf-8"))
        # The owner's own Git address is required by the identity rules, so it is the one
        # expected finding. Anything else is either a leak or a detector regression.
        unexpected = [f for f in result.findings if str(f.rule_id) != "pii.email"]
        assert unexpected == [], [f.to_dict() for f in unexpected]

    def test_the_only_address_in_it_is_the_owners(self) -> None:
        addresses = set(
            re.findall(
                r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                PROMPT.read_text(encoding="utf-8"),
            )
        )
        assert addresses == {"cheellasreeharsha2803@gmail.com"}
