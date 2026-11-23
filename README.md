# ISO 20022 Payment Sentinel

A real-time pre-settlement security and anomaly screening toolkit for ISO 20022 (`pacs.008`) financial payment messages.

## Capabilities
- **ISO 20022 XML Parsing:** Extracts debtor/creditor metadata, IBANs, BICs, amounts, currencies, and timestamps from `pacs.008` messages.
- **Identifier Validation:** ISO 13616 MOD-97 IBAN checksum validation and ISO 9362 BIC format checks.
- **Sanctions & Watchlist Screening:** Fuzzy entity name matching and high-risk jurisdiction checks.
- **Fraud & AML Anomaly Detection:** Structuring/smurfing detection (sub-\$10k threshold), velocity bursts, and off-hours high-value wire alerts.
- **Tamper-Evident Audit Chain:** SHA-256 hash-chained ledger of every screening decision for non-repudiation.

## Quick Start

```bash
python3 -m payment_sentinel.cli examples/sample_pacs008_clean.xml
python3 -m payment_sentinel.cli examples/sample_pacs008_suspicious.xml
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
