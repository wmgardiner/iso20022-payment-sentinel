"""ISO 20022 pacs.008 XML payment message parser."""

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
import xml.etree.ElementTree as ET


@dataclass(frozen=True)
class PaymentInstruction:
    """Normalized representation of an ISO 20022 pacs.008 credit transfer."""

    msg_id: str
    end_to_end_id: str
    amount: Decimal
    currency: str
    debtor_name: str
    debtor_iban: str
    debtor_bic: str
    creditor_name: str
    creditor_iban: str
    creditor_bic: str
    creditor_country: str
    created_at: datetime


def _find_text(root: ET.Element, local_path: str, default: str = "") -> str:
    """Find text using namespace-agnostic local tag matching."""
    parts = local_path.split("/")
    current = root
    for part in parts:
        found = None
        for child in current:
            tag = child.tag.split("}")[-1]
            if tag == part:
                found = child
                break
        if found is None:
            return default
        current = found
    return (current.text or "").strip()


def _find_element(root: ET.Element, local_path: str) -> ET.Element | None:
    parts = local_path.split("/")
    current = root
    for part in parts:
        found = None
        for child in current:
            tag = child.tag.split("}")[-1]
            if tag == part:
                found = child
                break
        if found is None:
            return None
        current = found
    return current


def parse_pacs008(xml_payload: str) -> PaymentInstruction:
    """Parse an ISO 20022 pacs.008 XML document into a PaymentInstruction."""
    root = ET.fromstring(xml_payload)
    body = _find_element(root, "FIToFICstmrCdtTrf")
    if body is None:
        raise ValueError("Missing FIToFICstmrCdtTrf element in ISO 20022 message.")

    msg_id = _find_text(body, "GrpHdr/MsgId")
    cre_dt_tm = _find_text(body, "GrpHdr/CreDtTm")
    tx = _find_element(body, "CdtTrfTxInf")
    if tx is None:
        raise ValueError("Missing CdtTrfTxInf transaction block.")

    amt_el = _find_element(tx, "IntrBkSttlmAmt")
    if amt_el is None or not (amt_el.text or "").strip():
        raise ValueError("Missing IntrBkSttlmAmt element.")

    currency = amt_el.attrib.get("Ccy", "USD")
    amount = Decimal(amt_el.text.strip())

    if cre_dt_tm:
        created_at = datetime.fromisoformat(cre_dt_tm.replace("Z", "+00:00"))
    else:
        created_at = datetime.now(timezone.utc)

    return PaymentInstruction(
        msg_id=msg_id,
        end_to_end_id=_find_text(tx, "PmtId/EndToEndId"),
        amount=amount,
        currency=currency,
        debtor_name=_find_text(tx, "Dbtr/Nm"),
        debtor_iban=_find_text(tx, "DbtrAcct/Id/IBAN"),
        debtor_bic=_find_text(tx, "DbtrAgt/FinInstnId/BICFI"),
        creditor_name=_find_text(tx, "Cdtr/Nm"),
        creditor_iban=_find_text(tx, "CdtrAcct/Id/IBAN"),
        creditor_bic=_find_text(tx, "CdtrAgt/FinInstnId/BICFI"),
        creditor_country=_find_text(tx, "Cdtr/PstlAdr/Ctry"),
        created_at=created_at,
    )
