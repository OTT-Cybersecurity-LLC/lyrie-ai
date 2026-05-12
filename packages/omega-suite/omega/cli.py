"""
lyrie-omega CLI entry point.
Provides the `lyrie-omega` command installed via pyproject.toml [project.scripts].
"""

import argparse
import sys

from omega import __version__, __description__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lyrie-omega",
        description=__description__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  lyrie-omega --version\n"
            "  lyrie-omega info\n"
            "\n"
            "Documentation: https://lyrie.ai/omega\n"
            "Issues:        https://github.com/OTT-Cybersecurity-LLC/lyrie-ai/issues\n"
        ),
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"lyrie-omega {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # info subcommand
    subparsers.add_parser(
        "info",
        help="Display package information and runtime details",
    )

    return parser


def cmd_info() -> None:
    import platform
    print(f"lyrie-omega  v{__version__}")
    print(f"Python       {sys.version.split()[0]}  ({platform.python_implementation()})")
    print(f"Platform     {platform.system()} {platform.machine()}")
    print(f"Author       OTT Cybersecurity LLC <dev@lyrie.ai>")
    print(f"Homepage     https://lyrie.ai")
    print(f"Docs         https://lyrie.ai/omega")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "info":
        cmd_info()
    elif args.command is None:
        parser.print_help()
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
