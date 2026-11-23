"""Unified pre-settlement risk scoring and decisioning engine."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from payment_sentinel.audit import AuditEntry, AuditLedger
from payment_sentinel.detectors import (
    AnomalyAlert,
    detect_off_hours_high_value,
    detect_structuring,
    detect_velocity_burst,
)
from payment_sentinel.parser import PaymentInstruction
from payment_sentinel.sanctions import SanctionsHit, SanctionsScreener
from payment_sentinel.validators import validate_payment_identifiers


@dataclass(frozen=True)
class ScreeningResult:
    msg_id: str
    decision: str  # ALLOW, REVIEW, BLOCK
    risk_score: int
    validation_errors: List[str]
    sanctions_hits: List[SanctionsHit]
    anomalies: List[AnomalyAlert]
    audit_entry: AuditEntry

    def to_dict(self) -> Dict[str, Any]:
        return {
            "msg_id": self.msg_id,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "validation_errors": self.validation_errors,
            "sanctions_hits": [
                {
                    "field": h.field,
                    "matched_value": h.matched_value,
                    "watchlist_entry": h.watchlist_entry,
                    "similarity": h.similarity,
                    "reason": h.reason,
                }
                for h in self.sanctions_hits
            ],
            "anomalies": [
                {
                    "code": a.code,
                    "severity": a.severity,
                    "score_delta": a.score_delta,
                    "message": a.message,
                }
                for a in self.anomalies
            ],
            "audit_entry": self.audit_entry.to_dict(),
        }


class PaymentSentinelEngine:
    """Evaluates ISO 20022 payment instructions and logs immutable audit records."""

    def __init__(
        self,
        screener: Optional[SanctionsScreener] = None,
        ledger: Optional[AuditLedger] = None,
    ) -> None:
        self.screener = screener or SanctionsScreener()
        self.ledger = ledger or AuditLedger()

    def evaluate(
        self,
        payment: PaymentInstruction,
        recent_history: Sequence[PaymentInstruction] = (),
    ) -> ScreeningResult:
        validation_errors = validate_payment_identifiers(payment)
        sanctions_hits = self.screener.screen(payment)
        anomalies: List[AnomalyAlert] = []
        anomalies.extend(detect_structuring(payment))
        anomalies.extend(detect_off_hours_high_value(payment))
        anomalies.extend(detect_velocity_burst(payment, recent_history))

        risk_score = (
            len(validation_errors) * 35
            + len(sanctions_hits) * 80
            + sum(a.score_delta for a in anomalies)
        )
        risk_score = min(risk_score, 100)

        if sanctions_hits or risk_score >= 75:
            decision = "BLOCK"
        elif risk_score >= 30:
            decision = "REVIEW"
        else:
            decision = "ALLOW"

        audit_entry = self.ledger.record(payment.msg_id, decision, risk_score)
        return ScreeningResult(
            msg_id=payment.msg_id,
            decision=decision,
            risk_score=risk_score,
            validation_errors=validation_errors,
            sanctions_hits=sanctions_hits,
            anomalies=anomalies,
            audit_entry=audit_entry,
        )
