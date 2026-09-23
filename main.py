"""Entry point: ``python main.py <subcommand> ...`` -> dnstester CLI."""

from dnstester.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
