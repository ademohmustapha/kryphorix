"""
kryphorix_entry.py — Package entry point for pip-installed `kryphorix` command.
Delegates to kryphorix.py main execution so both
  python kryphorix.py
  kryphorix          (after pip install)
work identically.
"""
import sys
import os
import runpy


def main():
    """Entry point called by the installed kryphorix console script."""
    # Ensure the installed package root is on sys.path
    pkg_root = os.path.dirname(os.path.abspath(__file__))
    if pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)

    # Execute kryphorix.py as __main__
    runpy.run_path(
        os.path.join(pkg_root, "kryphorix.py"),
        run_name="__main__"
    )


if __name__ == "__main__":
    main()
