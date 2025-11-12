"""Command line interface for the Safeline alert analyser."""
from __future__ import annotations

import argparse
import pathlib
from typing import Optional

import pandas as pd

from .analyzer import analyze_alerts


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analyse Safeline web attack alerts and export suspected false positives to a new Excel "
            "workbook."
        )
    )
    parser.add_argument("input", type=pathlib.Path, help="Path to the input Excel file.")
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("suspected_false_positives.xlsx"),
        help="Destination Excel file for the benign alerts (default: %(default)s).",
    )
    parser.add_argument(
        "--sheet",
        default=0,
        help=(
            "Name or index of the sheet in the workbook to analyse (default: 0, meaning the first "
            "sheet)."
        ),
    )
    parser.add_argument(
        "--payload-column",
        default="payload",
        help="Name of the column that contains the attack payload (default: payload).",
    )
    parser.add_argument(
        "--fallback-column",
        default="website",
        help="Column to analyse when the payload column is missing (default: website).",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.input.exists():
        parser.error(f"Input file '{args.input}' does not exist.")

    df = pd.read_excel(args.input, sheet_name=args.sheet)
    annotated_df, benign_df = analyze_alerts(
        df, payload_column=args.payload_column, fallback_column=args.fallback_column
    )

    if benign_df.empty:
        print("No benign alerts detected; no Excel file was generated.")
        return 0

    benign_df.to_excel(args.output, index=False)
    print(
        "Analysed %s alerts: %s malicious, %s benign. Exported benign alerts to %s" % (
            len(annotated_df),
            annotated_df["analysis_is_malicious"].sum(),
            len(benign_df),
            args.output,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
