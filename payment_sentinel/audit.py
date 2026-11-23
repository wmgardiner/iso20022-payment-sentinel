"""Tamper-evident SHA-256 hash-chained audit ledger for payment screening decisions."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    index: int
    timestamp: str
    msg_id: str
    decision: str
    risk_score: int
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "msg_id": self.msg_id,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


class AuditLedger:
    """Append-only hash-chained ledger ensuring non-repudiation of screening logs."""

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []

    @staticmethod
    def _compute_hash(
        index: int,
        timestamp: str,
        msg_id: str,
        decision: str,
        risk_score: int,
        prev_hash: str,
    ) -> str:
        payload = json.dumps(
            {
                "index": index,
                "timestamp": timestamp,
                "msg_id": msg_id,
                "decision": decision,
                "risk_score": risk_score,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def record(self, msg_id: str, decision: str, risk_score: int) -> AuditEntry:
        index = len(self._entries)
        timestamp = datetime.now(timezone.utc).isoformat()
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        entry_hash = self._compute_hash(
            index, timestamp, msg_id, decision, risk_score, prev_hash
        )
        entry = AuditEntry(
            index=index,
            timestamp=timestamp,
            msg_id=msg_id,
            decision=decision,
            risk_score=risk_score,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def verify_integrity(self) -> bool:
        """Recompute every link in the chain and verify zero tampering."""
        expected_prev = GENESIS_HASH
        for idx, entry in enumerate(self._entries):
            if entry.index != idx or entry.prev_hash != expected_prev:
                return False
            recomputed = self._compute_hash(
                entry.index,
                entry.timestamp,
                entry.msg_id,
                entry.decision,
                entry.risk_score,
                entry.prev_hash,
            )
            if recomputed != entry.entry_hash:
                return False
            expected_prev = entry.entry_hash
        return True

    @property
    def entries(self) -> List[AuditEntry]:
        return list(self._entries)
