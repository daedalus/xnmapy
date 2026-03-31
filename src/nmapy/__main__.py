from nmapy.cli import main as cli_main


def main() -> int:
    result = cli_main()
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
