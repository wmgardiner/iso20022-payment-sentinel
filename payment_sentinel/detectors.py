"""Behavioral and AML anomaly detectors for ISO 20022 wire instructions."""

from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import List, Sequence

from payment_sentinel.parser import PaymentInstruction


@dataclass(frozen=True)
class AnomalyAlert:
    code: str
    severity: str
    score_delta: int
    message: str


def detect_structuring(
    payment: PaymentInstruction,
    reporting_threshold: Decimal = Decimal("10000"),
) -> List[AnomalyAlert]:
    """Flag amounts just below the $10,000 regulatory reporting threshold (smurfing)."""
    lower_bound = reporting_threshold * Decimal("0.88")
    if lower_bound <= payment.amount < reporting_threshold:
        return [
            AnomalyAlert(
                code="AML-STRUCTURING",
                severity="high",
                score_delta=45,
                message=(
                    f"Amount {payment.amount} {payment.currency} falls within structuring "
                    f"band below {reporting_threshold} reporting threshold."
                ),
            )
        ]
    return []


def detect_off_hours_high_value(
    payment: PaymentInstruction,
    high_value_threshold: Decimal = Decimal("50000"),
) -> List[AnomalyAlert]:
    """Flag high-value transfers initiated outside standard UTC settlement hours (22:00-05:00)."""
    hour = payment.created_at.hour
    is_off_hours = hour >= 22 or hour < 5
    if is_off_hours and payment.amount >= high_value_threshold:
        return [
            AnomalyAlert(
                code="WIRE-OFF-HOURS",
                severity="medium",
                score_delta=30,
                message=(
                    f"High-value transfer ({payment.amount} {payment.currency}) initiated "
                    f"at {payment.created_at.isoformat()} outside normal settlement window."
                ),
            )
        ]
    return []


def detect_velocity_burst(
    payment: PaymentInstruction,
    recent_history: Sequence[PaymentInstruction],
    window_minutes: int = 15,
    max_tx_in_window: int = 3,
) -> List[AnomalyAlert]:
    """Flag rapid-fire transfers from the same debtor IBAN within a short time window."""
    window_start = payment.created_at - timedelta(minutes=window_minutes)
    same_debtor = [
        tx
        for tx in recent_history
        if tx.debtor_iban == payment.debtor_iban
        and window_start <= tx.created_at <= payment.created_at
    ]
    if len(same_debtor) >= max_tx_in_window:
        return [
            AnomalyAlert(
                code="WIRE-VELOCITY-BURST",
                severity="high",
                score_delta=40,
                message=(
                    f"Debtor {payment.debtor_iban} sent {len(same_debtor) + 1} wires "
                    f"within {window_minutes} minutes."
                ),
            )
        ]
    return []


def detect_round_dollar_high_value(
    payment: PaymentInstruction,
    min_amount: Decimal = Decimal("25000"),
) -> List[AnomalyAlert]:
    """Flag large exact-thousand round-dollar transfers common in shell-company layering."""
    if payment.amount >= min_amount and payment.amount % Decimal("1000") == 0:
        return [
            AnomalyAlert(
                code="AML-ROUND-HIGH-VALUE",
                severity="medium",
                score_delta=25,
                message=(
                    f"High-value exact-thousand transfer ({payment.amount} {payment.currency}) "
                    "matches common layering heuristic."
                ),
            )
        ]
    return []


def detect_cross_border_high_value_fx(
    payment: PaymentInstruction,
    home_currency: str = "AUD",
    fx_threshold: Decimal = Decimal("20000"),
) -> List[AnomalyAlert]:
    """Flag high-value non-home-currency cross-border transfers for enhanced due diligence."""
    if payment.currency.upper() != home_currency.upper() and payment.amount >= fx_threshold:
        return [
            AnomalyAlert(
                code="FX-HIGH-VALUE",
                severity="medium",
                score_delta=20,
                message=(
                    f"Cross-border FX transfer of {payment.amount} {payment.currency} "
                    f"exceeds {fx_threshold} enhanced due diligence threshold."
                ),
            )
        ]
    return []
