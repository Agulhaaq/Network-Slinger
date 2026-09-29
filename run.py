#!/usr/bin/env python3
"""
Network Slinger - Root Entrypoint Script.
Execute directly:
    python run.py crawl
    python run.py web
    python run.py ifaces
"""

import os
import sys

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure package is resolvable from root
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from networkslinger.cli import main

if __name__ == "__main__":
    main()
