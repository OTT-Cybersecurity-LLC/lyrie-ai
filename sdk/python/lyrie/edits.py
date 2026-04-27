"""
Lyrie EditEngine — Python port.

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.

Diff-view file edits with approval gates. oldText -> newText replacements
that must be unique. Shield-scans every patch BEFORE the file is touched.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Iterable, Literal, Optional

from lyrie.shield import Shield

EDIT_ENGINE_VERSION: Final[str] = "lyrie-edit-engine-py-1.0.0"
SIGNATURE: Final[str] = "Lyrie.ai by OTT Cybersecurity LLC"

ApprovalMode = Literal["auto-approve", "require-approval", "dry-run"]


@dataclass(slots=True)
class EditOp:
    old_text: str
    new_text: str


@dataclass(slots=True)
class EditPlan:
    id: str
    path: str
    description: Optional[str]
    mode: ApprovalMode
    before_hash: str
    after_content: str
    unified_diff: str
    edit_count: int
    applicable: bool
    detail: list[dict[str, object]]
    shielded: bool = False
    shield_reason: Optional[str] = None
    created_at: str = ""
    signature: str = SIGNATURE


@dataclass(slots=True)
class EditApply:
    id: str
    path: str
    before_hash: str
    after_hash: str
    bytes_before: int
    bytes_after: int
    applied_at: str
    description: Optional[str] = None


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _count_occurrences(haystack: str, needle: str) -> int:
    if not needle:
        return 0
    return haystack.count(needle)


class EditEngine:
    """
    Lyrie EditEngine — Python port.

    Lyrie.ai by OTT Cybersecurity LLC.
    """

    __slots__ = ("_default_mode", "_workspace", "_shield", "_pending", "_applied")

    def __init__(
        self,
        *,
        default_mode: ApprovalMode = "require-approval",
        workspace_root: str | Path = ".",
        shield: Optional[Shield] = None,
    ) -> None:
        self._default_mode: ApprovalMode = default_mode
        self._workspace = Path(workspace_root).resolve()
        self._shield = shield or Shield()
        self._pending: list[EditPlan] = []
        self._applied: list[EditApply] = []

    def plan(
        self,
        path: str,
        edits: Iterable[EditOp],
        *,
        description: Optional[str] = None,
        mode: Optional[ApprovalMode] = None,
    ) -> EditPlan:
        target = self._resolve(path)
        original = target.read_text("utf-8") if target.is_file() else ""
        before_hash = _sha256(original)

        after = original
        detail: list[dict[str, object]] = []
        applicable = True
        edits_list = list(edits)
        for i, e in enumerate(edits_list):
            occ = _count_occurrences(after, e.old_text)
            if occ == 0:
                detail.append({"index": i, "matched": False, "reason": "old_text not found"})
                applicable = False
                continue
            if occ > 1:
                detail.append({
                    "index": i, "matched": False,
                    "reason": f"old_text not unique ({occ} matches)",
                })
                applicable = False
                continue
            after = after.replace(e.old_text, e.new_text, 1)
            detail.append({"index": i, "matched": True})

        verdict = self._shield.scan_recalled(after)
        diff = ""
        if applicable and original != after:
            diff = "".join(difflib.unified_diff(
                original.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile=f"a/{path}", tofile=f"b/{path}", n=3,
            ))

        plan = EditPlan(
            id=str(uuid.uuid4()),
            path=str(target),
            description=description,
            mode=mode or self._default_mode,
            before_hash=before_hash,
            after_content=after,
            unified_diff=diff,
            edit_count=len(edits_list),
            applicable=applicable,
            detail=detail,
            shielded=verdict.blocked,
            shield_reason=verdict.reason,
            created_at=datetime.now(tz=timezone.utc).isoformat(),
        )

        if plan.mode == "require-approval" and plan.applicable and not plan.shielded:
            self._pending.append(plan)
        return plan

    def apply(self, plan: EditPlan, *, force: bool = False) -> Optional[EditApply]:
        if not plan.applicable:
            return None
        if plan.shielded and not force:
            return None
        if plan.mode == "dry-run":
            return None
        if plan.mode == "require-approval" and not force:
            return None

        path = Path(plan.path)
        current = path.read_text("utf-8") if path.is_file() else ""
        if _sha256(current) != plan.before_hash:
            return None

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(plan.after_content, "utf-8")

        applied = EditApply(
            id=plan.id, path=str(path),
            before_hash=plan.before_hash, after_hash=_sha256(plan.after_content),
            bytes_before=len(current.encode("utf-8")),
            bytes_after=len(plan.after_content.encode("utf-8")),
            applied_at=datetime.now(tz=timezone.utc).isoformat(),
            description=plan.description,
        )
        self._applied.append(applied)
        self._pending = [p for p in self._pending if p.id != plan.id]
        return applied

    def approve(self, plan_id: str) -> Optional[EditApply]:
        for plan in self._pending:
            if plan.id == plan_id:
                return self.apply(plan, force=True)
        return None

    def pending(self) -> list[EditPlan]:
        return list(self._pending)

    def applied(self) -> list[EditApply]:
        return list(self._applied)

    def _resolve(self, p: str) -> Path:
        target = (self._workspace / p).resolve()
        if not str(target).startswith(str(self._workspace)):
            raise PermissionError(f"refusing path outside workspace: {p}")
        return target
