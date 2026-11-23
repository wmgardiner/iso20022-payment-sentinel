"""Fuzzy watchlist and high-risk jurisdiction sanctions screening."""

from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Iterable, List, Set

from payment_sentinel.parser import PaymentInstruction

DEFAULT_WATCHLIST = (
    "ACME SHELL HOLDINGS LTD",
    "NORTHERN CORRIDOR TRADING LLC",
    "VORTEX OFFSHORE SYNDICATE",
)

HIGH_RISK_JURISDICTIONS: Set[str] = {"KP", "IR", "SY"}


@dataclass(frozen=True)
class SanctionsHit:
    field: str
    matched_value: str
    watchlist_entry: str
    similarity: float
    reason: str


class SanctionsScreener:
    """Performs fuzzy entity matching and jurisdiction screening on payment parties."""

    def __init__(
        self,
        watchlist: Iterable[str] = DEFAULT_WATCHLIST,
        high_risk_countries: Iterable[str] = HIGH_RISK_JURISDICTIONS,
        threshold: float = 0.82,
    ) -> None:
        self.watchlist = [w.strip().upper() for w in watchlist]
        self.high_risk_countries = {c.strip().upper() for c in high_risk_countries}
        self.threshold = threshold

    def _fuzzy_match(self, field: str, candidate: str) -> List[SanctionsHit]:
        normalized = candidate.strip().upper()
        if not normalized:
            return []
        hits: List[SanctionsHit] = []
        for entry in self.watchlist:
            score = SequenceMatcher(None, normalized, entry).ratio()
            if score >= self.threshold:
                hits.append(
                    SanctionsHit(
                        field=field,
                        matched_value=candidate,
                        watchlist_entry=entry,
                        similarity=round(score, 3),
                        reason=f"Fuzzy watchlist match ({score:.2%}) against '{entry}'",
                    )
                )
        return hits

    def screen(self, payment: PaymentInstruction) -> List[SanctionsHit]:
        hits: List[SanctionsHit] = []
        hits.extend(self._fuzzy_match("debtor_name", payment.debtor_name))
        hits.extend(self._fuzzy_match("creditor_name", payment.creditor_name))

        country = payment.creditor_country.strip().upper()
        if country and country in self.high_risk_countries:
            hits.append(
                SanctionsHit(
                    field="creditor_country",
                    matched_value=country,
                    watchlist_entry=country,
                    similarity=1.0,
                    reason=f"Creditor jurisdiction '{country}' is on high-risk sanctions list.",
                )
            )
        return hits
