"""
Terraform AWS Best-Practice Evaluator
--------------------------------------
Usage:
  python main.py --dir ../terraform
  python main.py --dir ../terraform --live --region ap-northeast-1
  python main.py --dir ../terraform --live --profile myprofile --output report.json
"""

import argparse
import json
import sys
from pathlib import Path

# Make imports work when running from this directory
sys.path.insert(0, str(Path(__file__).parent))

from hcl_parser import parse_tf_directory
from evaluator import evaluate_static, compare_live, generate_report, generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate Terraform configurations against AWS best practices."
    )
    parser.add_argument(
        "--dir",
        default="../terraform",
        help="Path to the Terraform directory (default: ../terraform)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Also compare against live AWS state via boto3",
    )
    parser.add_argument(
        "--region",
        default="ap-northeast-1",
        help="AWS region for live checks (default: ap-northeast-1)",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS CLI profile name (default: use environment credentials)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Save findings as JSON to this file path",
    )
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity to display (default: LOW)",
    )
    parser.add_argument(
        "--output-html",
        default=None,
        metavar="FILE",
        help="Save HTML report to this file path (e.g. report.html)",
    )
    args = parser.parse_args()

    tf_dir = str(Path(args.dir).resolve())
    print(f"\nEvaluating: {tf_dir}")
    print("-" * 50)

    # ── Parse .tf files ──────────────────────────
    print("Parsing Terraform files...")
    try:
        resources, variables = parse_tf_directory(tf_dir)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    resource_summary = {rtype: len(inst) for rtype, inst in resources.items()}
    print(f"  Resource types found: {len(resource_summary)}")
    for rtype, count in sorted(resource_summary.items()):
        print(f"    {rtype}: {count}")
    print()

    # ── Static evaluation ─────────────────────────
    print("Running static rule checks...")
    result = evaluate_static(resources)
    print(f"  Static findings: {len(result.findings)}")
    print()

    # ── Live AWS comparison ───────────────────────
    if args.live:
        print(f"Connecting to AWS ({args.region})...")
        compare_live(result, resources, region=args.region, profile=args.profile)
        print()

    # ── Filter by severity ────────────────────────
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    min_idx = severity_order.index(args.min_severity)
    result.findings = [
        f for f in result.findings
        if severity_order.index(f.severity) <= min_idx
    ]

    # ── Report ────────────────────────────────────
    report_text = generate_report(result, resources, variables)
    sys.stdout.buffer.write((report_text + "\n").encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()

    # ── JSON output ───────────────────────────────
    if args.output:
        output_path = Path(args.output)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, ensure_ascii=False, indent=2)
        print(f"JSON report saved to: {output_path.resolve()}")

    # ── HTML output ───────────────────────────────
    if args.output_html:
        html_path = Path(args.output_html)
        html_content = generate_html_report(result, resources, variables, tf_dir=tf_dir)
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"HTML report saved to: {html_path.resolve()}")

    # Exit with non-zero if critical/high issues found
    critical_high = len(result.by_severity("CRITICAL")) + len(result.by_severity("HIGH"))
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == "__main__":
    main()
