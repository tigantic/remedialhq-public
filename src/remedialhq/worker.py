from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .phases import PHASE_ORDER, run_phase


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m remedialhq.worker")
    parser.add_argument("phase", choices=PHASE_ORDER)
    parser.add_argument("--root", default=os.environ.get("APP_ROOT", "."))
    parser.add_argument("--output", default=os.environ.get("WORKSPACE", "/tmp/remedialhq"))
    args = parser.parse_args()
    result = run_phase(args.phase, Path(args.root), Path(args.output))
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    raise SystemExit(0 if result.status in {"PASS", "HOLD"} else 2)


if __name__ == "__main__":
    main()
