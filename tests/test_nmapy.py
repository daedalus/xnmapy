from nmapy._core import NmapScan, ScanOptions
from nmapy.parsers import PortParser, TargetParser


class TestTargetParser:
    def test_parse_single_ipv4(self) -> None:
        parser = TargetParser()
        result = parser.parse("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_parse_hostname(self) -> None:
        parser = TargetParser()
        result = parser.parse("scanme.nmapy.org")
        assert result == ["scanme.nmapy.org"]

    def test_parse_cidr(self) -> None:
        parser = TargetParser()
        result = parser.parse("192.168.1.0/30")
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_parse_range(self) -> None:
        parser = TargetParser()
        result = parser.parse("192.168.1.1-3")
        assert len(result) == 3
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        assert "192.168.1.3" in result

    def test_parse_empty_string(self) -> None:
        parser = TargetParser()
        result = parser.parse("")
        assert result == []

    def test_parse_invalid_ipv4(self) -> None:
        parser = TargetParser()
        result = parser.parse("256.256.256.256")
        assert result == ["256.256.256.256"]

    def test_parse_multiple_targets(self) -> None:
        parser = TargetParser()
        result = parser.parse_multiple("192.168.1.1,10.0.0.1")
        assert len(result) == 2

    def test_parse_multiple_with_semicolon(self) -> None:
        parser = TargetParser()
        result = parser.parse_multiple("192.168.1.1;10.0.0.1")
        assert len(result) == 2


class TestPortParser:
    def test_parse_single_port(self) -> None:
        parser = PortParser()
        result = parser.parse("80")
        assert len(result) == 1
        assert result[0]["port"] == 80

    def test_parse_multiple_ports(self) -> None:
        parser = PortParser()
        result = parser.parse("22,80,443")
        assert len(result) == 3

    def test_parse_port_range(self) -> None:
        parser = PortParser()
        result = parser.parse("80-82")
        assert len(result) == 3

    def test_parse_udp_port(self) -> None:
        parser = PortParser()
        result = parser.parse("U:53")
        assert len(result) == 1
        assert result[0]["protocol"] == "udp"
        assert result[0]["port"] == 53

    def test_parse_tcp_port(self) -> None:
        parser = PortParser()
        result = parser.parse("T:80")
        assert len(result) == 1
        assert result[0]["protocol"] == "tcp"

    def test_parse_sctp_port(self) -> None:
        parser = PortParser()
        result = parser.parse("S:22")
        assert len(result) == 1
        assert result[0]["protocol"] == "sctp"

    def test_parse_invalid_port_high(self) -> None:
        parser = PortParser()
        result = parser.parse("70000")
        assert result == []

    def test_parse_invalid_port_zero(self) -> None:
        parser = PortParser()
        result = parser.parse("0")
        assert result == []

    def test_parse_invalid_port_negative(self) -> None:
        parser = PortParser()
        result = parser.parse("-1")
        assert result == []


class TestScanOptions:
    def test_default_options(self) -> None:
        opts = ScanOptions()
        assert opts.targets == []
        assert opts.verbose == 0

    def test_options_with_targets(self) -> None:
        opts = ScanOptions(targets=["192.168.1.1"])
        assert opts.targets == ["192.168.1.1"]

    def test_options_with_ports(self) -> None:
        opts = ScanOptions(ports="80,443")
        assert opts.ports == "80,443"


class TestNmapScan:
    def test_scan_with_single_target(self) -> None:
        opts = ScanOptions(targets=["192.168.1.1"])
        scan = NmapScan(opts)
        result = scan.run()
        assert result.targets == ["192.168.1.1"]

    def test_scan_with_no_targets(self) -> None:
        opts = ScanOptions()
        scan = NmapScan(opts)
        result = scan.run()
        assert result.targets == []

    def test_scan_with_ports(self) -> None:
        opts = ScanOptions(targets=["192.168.1.1"], ports="80")
        scan = NmapScan(opts)
        result = scan.run()
        assert len(result.ports) == 1
        assert result.ports[0].port == 80

    def test_scan_excludes_hosts(self) -> None:
        opts = ScanOptions(
            targets=["192.168.1.1", "192.168.1.2"], exclude_hosts="192.168.1.1"
        )
        scan = NmapScan(opts)
        result = scan.run()
        assert "192.168.1.1" not in result.targets
        assert "192.168.1.2" in result.targets

    def test_scan_random_hosts_limited(self) -> None:
        opts = ScanOptions(random_hosts=15000)
        scan = NmapScan(opts)
        result = scan.run()
        assert len(result.targets) == 10000

    def test_scan_output_format(self) -> None:
        opts = ScanOptions(targets=["192.168.1.1"])
        scan = NmapScan(opts)
        result = scan.run()
        assert "Nmap scan report" in result.raw_output


class TestNmapScanEdgeCases:
    def test_read_nonexistent_file(self) -> None:
        opts = ScanOptions(input_list="/nonexistent/file.txt")
        scan = NmapScan(opts)
        result = scan.run()
        assert result.targets == []

    def test_exclude_file_nonexistent(self) -> None:
        opts = ScanOptions(
            targets=["192.168.1.1"], exclude_file="/nonexistent/file.txt"
        )
        scan = NmapScan(opts)
        result = scan.run()
        assert result.targets == ["192.168.1.1"]

    def test_empty_target_after_exclusion(self) -> None:
        opts = ScanOptions(targets=["192.168.1.1"], exclude_hosts="192.168.1.1")
        scan = NmapScan(opts)
        result = scan.run()
        assert result.targets == []

    def test_invalid_port_spec(self) -> None:
        opts = ScanOptions(targets=["192.168.1.1"], ports="invalid")
        scan = NmapScan(opts)
        result = scan.run()
        assert result.ports == []


def test_version_attribute() -> None:
    from nmapy import __version__

    assert __version__ == "0.1.0"


def test_import_nmapy() -> None:
    import nmapy

    assert nmapy.__version__ == "0.1.0"
