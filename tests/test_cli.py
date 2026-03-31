from click.testing import CliRunner

from nmapy.cli import main


class TestCLI:
    def test_version_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["-V"])
        assert result.exit_code == 0
        assert "Nmapy version 0.1.0" in result.output

    def test_help_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["-h"])
        assert result.exit_code == 0
        assert "Nmapy" in result.output

    def test_iflist_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--iflist", "192.168.1.1"])
        assert result.exit_code == 0
        assert "Interface List" in result.output

    def test_no_targets_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0

    def test_scan_with_target(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["192.168.1.1"])
        assert result.exit_code == 0

    def test_scan_with_ports(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["-p", "80", "192.168.1.1"])
        assert result.exit_code == 0

    def test_scan_with_scan_type(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["-sS", "192.168.1.1"])
        assert result.exit_code == 0

    def test_scan_with_verbose(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["-v", "192.168.1.1"])
        assert result.exit_code == 0
