from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

VALID_STATUS = frozenset({"DONE", "TODO", "LATER", "WAIVED"})


def load_execution_plan(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("execution plan must be a JSON object")
    tasks = payload.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise ValueError("execution plan must contain tasks")
    ids: set[str] = set()
    for task in tasks:
        if not isinstance(task, dict):
            raise TypeError("execution plan task must be an object")
        task_id = str(task.get("task_id", ""))
        status = str(task.get("status", ""))
        if not task_id or task_id in ids:
            raise ValueError(f"invalid or duplicate task ID: {task_id}")
        if status not in VALID_STATUS:
            raise ValueError(f"invalid status for {task_id}: {status}")
        ids.add(task_id)
    unknown = {
        dependency
        for task in tasks
        for dependency in task.get("depends_on", [])
        if dependency not in ids
    }
    if unknown:
        raise ValueError(f"unknown task dependencies: {sorted(unknown)}")
    return cast(dict[str, Any], payload)


def execution_summary(plan: dict[str, Any]) -> dict[str, Any]:
    tasks = list(plan["tasks"])
    by_id = {str(task["task_id"]): task for task in tasks}
    counts = {status: sum(task["status"] == status for task in tasks) for status in VALID_STATUS}
    ready = []
    for task in tasks:
        if task["status"] != "TODO":
            continue
        dependencies = [by_id[item]["status"] for item in task.get("depends_on", [])]
        if all(status in {"DONE", "WAIVED"} for status in dependencies):
            ready.append(task)
    return {
        "brand": plan.get("brand"),
        "as_of": plan.get("as_of"),
        "total": len(tasks),
        "counts": dict(sorted(counts.items())),
        "ready": ready,
    }
