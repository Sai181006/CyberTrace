"""Small, evidence-grounded analyst task set and answer scoring."""

from __future__ import annotations

import json
import re
from pathlib import Path

TASK_PATH = Path(__file__).resolve().parent.parent / "data" / "evaluation" / "tasks.json"


def _all_tasks() -> list[dict]:
    return json.loads(TASK_PATH.read_text(encoding="utf-8"))


def tasks_for_mode(mode: str) -> list[dict]:
    if mode not in {"graph", "reference"}:
        raise ValueError("Mode must be graph or reference")
    return [
        {
            "id": task["id"],
            "question": task["question"],
            **({"reference_context": task["reference_context"]} if mode == "reference" else {}),
        }
        for task in _all_tasks()
    ]


def grade(task_id: str, answer: str) -> tuple[bool, str]:
    task = next((item for item in _all_tasks() if item["id"] == task_id), None)
    if task is None:
        raise ValueError("Unknown evaluation task")
    if not isinstance(answer, str) or not 1 <= len(answer.strip()) <= 300:
        raise ValueError("Answer must be 1–300 characters")
    def normalize(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", value.casefold())
    return normalize(answer) in {normalize(value) for value in task["answers"]}, task["explanation"]
