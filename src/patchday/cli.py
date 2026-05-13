#!/usr/bin/env python3

import argparse
import json
import sys
from datetime import UTC, datetime

from patchday.dates import patch_tuesday, release_label
from patchday.msrc import (
    DEFAULT_TIMEOUT,
    make_session,
    msrc_data,
    msrc_details_for_vulns,
)
from patchday.tui import render_tui
from patchday.vulns import encode_vulns, filter_vulns, normalize, sort_key


def parse_month(value):
    try:
        parsed = datetime.strptime(value, "%Y-%m")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("month must use YYYY-MM format") from exc
    return parsed.year, parsed.month


def build_parser():
    today = datetime.now(UTC).date()
    default_month = f"{today.year:04d}-{today.month:02d}"

    parser = argparse.ArgumentParser(description="Pull Microsoft Patch Tuesday CVEs.")
    parser.add_argument(
        "--month",
        type=parse_month,
        default=parse_month(default_month),
        metavar="YYYY-MM",
        help=f"Patch Tuesday month to report, default: {default_month}",
    )
    parser.add_argument(
        "--all-severities",
        action="store_true",
        help="show every CVE instead of only Critical and Important entries",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit JSON instead of launching the TUI",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    year, month = args.month
    start_date = patch_tuesday(year, month)
    end_date = None
    release = release_label(year, month)
    generated_at = datetime.now(UTC)
    session = make_session()

    try:
        raw = msrc_data(session, DEFAULT_TIMEOUT, True)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    vulns = normalize(raw, release=release)
    vulns.sort(key=sort_key, reverse=True)
    shown_vulns = filter_vulns(vulns, args.all_severities)

    if args.json:
        details_by_cve = msrc_details_for_vulns(
            shown_vulns,
            timeout=DEFAULT_TIMEOUT,
            verify_tls=True,
        )
        output = {
            "generated": generated_at.isoformat(),
            "release_date": start_date.isoformat(),
            "release": release,
            "window_end": end_date.isoformat() if end_date else None,
            "total": len(shown_vulns),
            "vulnerabilities": encode_vulns(shown_vulns, details_by_cve),
        }
        print(
            json.dumps(
                output,
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    render_tui(
        shown_vulns,
        generated_at=generated_at,
        release=release,
        start_date=start_date,
        end_date=end_date,
        include_all=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
