"""Unit tests for ISO 20022 Payment Sentinel."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import unittest

from payment_sentinel.audit import AuditLedger
from payment_sentinel.engine import PaymentSentinelEngine
from payment_sentinel.parser import PaymentInstruction, parse_pacs008
from payment_sentinel.validators import is_valid_bic, is_valid_iban

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


class TestPaymentSentinel(unittest.TestCase):
    def test_iban_and_bic_validators(self) -> None:
        self.assertTrue(is_valid_iban("DE89370400440532013000"))
        self.assertTrue(is_valid_iban("GB82WEST12345698765432"))
        self.assertFalse(is_valid_iban("DE00370400440532013000"))
        self.assertTrue(is_valid_bic("COBADEFFXXX"))
        self.assertFalse(is_valid_bic("BADBIC"))

    def test_clean_pacs008_is_allowed(self) -> None:
        xml = (EXAMPLES_DIR / "sample_pacs008_clean.xml").read_text(encoding="utf-8")
        payment = parse_pacs008(xml)
        engine = PaymentSentinelEngine()
        result = engine.evaluate(payment)

        self.assertEqual(result.decision, "ALLOW")
        self.assertEqual(result.risk_score, 0)
        self.assertEqual(result.validation_errors, [])
        self.assertTrue(engine.ledger.verify_integrity())

    def test_suspicious_pacs008_is_blocked(self) -> None:
        xml = (EXAMPLES_DIR / "sample_pacs008_suspicious.xml").read_text(encoding="utf-8")
        payment = parse_pacs008(xml)
        engine = PaymentSentinelEngine()
        result = engine.evaluate(payment)

        self.assertEqual(result.decision, "BLOCK")
        self.assertGreaterEqual(len(result.sanctions_hits), 2)
        self.assertTrue(any(a.code == "AML-STRUCTURING" for a in result.anomalies))
        self.assertTrue(engine.ledger.verify_integrity())

    def test_velocity_burst_detection(self) -> None:
        base_time = datetime(2026, 11, 23, 14, 0, tzinfo=timezone.utc)
        history = [
            PaymentInstruction(
                msg_id=f"MSG-{i}",
                end_to_end_id=f"E2E-{i}",
                amount=Decimal("500.00"),
                currency="USD",
                debtor_name="FAST SENDER",
                debtor_iban="DE89370400440532013000",
                debtor_bic="COBADEFFXXX",
                creditor_name="RECIPIENT",
                creditor_iban="GB82WEST12345698765432",
                creditor_bic="NWBKGB2LXXX",
                creditor_country="GB",
                created_at=base_time + timedelta(minutes=i * 2),
            )
            for i in range(3)
        ]
        latest = PaymentInstruction(
            msg_id="MSG-BURST",
            end_to_end_id="E2E-BURST",
            amount=Decimal("500.00"),
            currency="USD",
            debtor_name="FAST SENDER",
            debtor_iban="DE89370400440532013000",
            debtor_bic="COBADEFFXXX",
            creditor_name="RECIPIENT",
            creditor_iban="GB82WEST12345698765432",
            creditor_bic="NWBKGB2LXXX",
            creditor_country="GB",
            created_at=base_time + timedelta(minutes=8),
        )
        engine = PaymentSentinelEngine()
        result = engine.evaluate(latest, recent_history=history)
        self.assertEqual(result.decision, "REVIEW")
        self.assertTrue(any(a.code == "WIRE-VELOCITY-BURST" for a in result.anomalies))

    def test_audit_ledger_detects_tampering(self) -> None:
        ledger = AuditLedger()
        ledger.record("MSG-1", "ALLOW", 0)
        ledger.record("MSG-2", "BLOCK", 95)
        self.assertTrue(ledger.verify_integrity())

        # Simulate tampering with an entry
        tampered = ledger._entries[0]
        ledger._entries[0] = tampered.__class__(
            index=tampered.index,
            timestamp=tampered.timestamp,
            msg_id=tampered.msg_id,
            decision="BLOCK",  # altered
            risk_score=tampered.risk_score,
            prev_hash=tampered.prev_hash,
            entry_hash=tampered.entry_hash,
        )
        self.assertFalse(ledger.verify_integrity())


if __name__ == "__main__":
    unittest.main()
