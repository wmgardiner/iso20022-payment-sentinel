"""CLI for screening ISO 20022 pacs.008 XML payment files."""

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

from payment_sentinel.engine import PaymentSentinelEngine
from payment_sentinel.parser import parse_pacs008


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="payment-sentinel",
        description="Screen ISO 20022 pacs.008 payment XML files for fraud, sanctions, and integrity.",
    )
    parser.add_argument("files", nargs="+", type=Path, help="One or more pacs.008 XML files.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    engine = PaymentSentinelEngine()
    history = []
    results = []
    blocked = False

    for xml_path in args.files:
        payment = parse_pacs008(xml_path.read_text(encoding="utf-8"))
        result = engine.evaluate(payment, recent_history=history)
        history.append(payment)
        results.append(result.to_dict())
        if result.decision == "BLOCK":
            blocked = True

    output = {
        "chain_verified": engine.ledger.verify_integrity(),
        "results": results,
    }
    print(json.dumps(output, indent=2))
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
