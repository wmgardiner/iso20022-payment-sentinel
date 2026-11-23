"""ISO 13616 IBAN and ISO 9362 BIC format/checksum validators."""

import re
from typing import List

from payment_sentinel.parser import PaymentInstruction

BIC_PATTERN = re.compile(r"^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$")


def is_valid_bic(bic: str) -> bool:
    """Validate an 8- or 11-character ISO 9362 BIC/SWIFT code."""
    return bool(BIC_PATTERN.match(bic.strip().upper()))


def is_valid_iban(iban: str) -> bool:
    """Validate an IBAN using the ISO 13616 MOD-97 checksum algorithm."""
    cleaned = re.sub(r"\s+", "", iban).upper()
    if len(cleaned) < 15 or len(cleaned) > 34 or not cleaned.isalnum():
        return False
    if not cleaned[:2].isalpha() or not cleaned[2:4].isdigit():
        return False

    rearranged = cleaned[4:] + cleaned[:4]
    numeric = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged)
    return int(numeric) % 97 == 1


def validate_payment_identifiers(payment: PaymentInstruction) -> List[str]:
    """Return a list of identifier validation errors for a payment instruction."""
    errors: List[str] = []
    if payment.debtor_iban and not is_valid_iban(payment.debtor_iban):
        errors.append(f"Invalid debtor IBAN checksum/format: {payment.debtor_iban}")
    if payment.creditor_iban and not is_valid_iban(payment.creditor_iban):
        errors.append(f"Invalid creditor IBAN checksum/format: {payment.creditor_iban}")
    if payment.debtor_bic and not is_valid_bic(payment.debtor_bic):
        errors.append(f"Invalid debtor BIC format: {payment.debtor_bic}")
    if payment.creditor_bic and not is_valid_bic(payment.creditor_bic):
        errors.append(f"Invalid creditor BIC format: {payment.creditor_bic}")
    if payment.amount <= 0:
        errors.append(f"Non-positive settlement amount: {payment.amount}")
    return errors
