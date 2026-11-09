"""Compatibility entry point; uses the same policy and CLI as app.py."""

from app import main


if __name__ == "__main__":
    raise SystemExit(main())
