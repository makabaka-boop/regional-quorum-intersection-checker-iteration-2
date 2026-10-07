"""命令行入口：从文件或标准输入读取 JSON，并输出分析结果。"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .analyzer import ValidationError, analyze


def run_analyzer(payload: Any) -> dict[str, Any]:
    return analyze(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze read/write quorum intersection from JSON input"
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="JSON input file, or '-' to read stdin (default: -)",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="spaces used to pretty-print JSON output (default: 2)",
    )
    args = parser.parse_args(argv)

    try:
        if args.input == "-":
            payload = json.load(sys.stdin)
        else:
            with open(args.input, "r", encoding="utf-8") as source:
                payload = json.load(source)
        result = run_analyzer(payload)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    json.dump(result, sys.stdout, ensure_ascii=False, indent=args.indent)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
