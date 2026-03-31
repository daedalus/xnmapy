import re


class TargetParser:
    def __init__(self) -> None:
        self.ipv4_pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        self.cidr_pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])$"
        )
        self.range_pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$"
        )

    def parse(self, target: str) -> list[str]:
        target = target.strip()
        if not target:
            return []
        if self._is_valid_ipv4(target):
            return [target]
        if self._is_cidr(target):
            return self._expand_cidr(target)
        if self._is_range(target):
            return self._expand_range(target)
        if self._is_hostname(target):
            return [target]
        return []

    def parse_multiple(self, targets: str) -> list[str]:
        results = []
        for target in targets.replace(";", ",").split(","):
            results.extend(self.parse(target))
        return results

    def _is_valid_ipv4(self, target: str) -> bool:
        return bool(self.ipv4_pattern.match(target))

    def _is_cidr(self, target: str) -> bool:
        return bool(self.cidr_pattern.match(target))

    def _is_range(self, target: str) -> bool:
        parts = target.split("-")
        if len(parts) != 2:
            return False
        start = parts[0].strip()
        end = parts[1].strip()
        if not self._is_valid_ipv4(start):
            return False
        if self._is_valid_ipv4(end):
            return True
        try:
            end_octet = int(end)
            if 0 <= end_octet <= 255:
                return True
        except ValueError:
            pass
        return False

    def _is_hostname(self, target: str) -> bool:
        hostname_pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        )
        return bool(hostname_pattern.match(target))

    def _expand_cidr(self, cidr: str) -> list[str]:
        ip_str, prefix_str = cidr.split("/")
        prefix: int = int(prefix_str)
        ip_parts: list[int] = list(map(int, ip_str.split(".")))
        ip_int = (
            (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]
        )
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        network = ip_int & mask
        broadcast = network | (~mask & 0xFFFFFFFF)
        results = []
        for i in range(network + 1, broadcast):
            results.append(self._int_to_ip(i))
        return results[:10000]

    def _expand_range(self, target: str) -> list[str]:
        start, end = target.split("-")
        start = start.strip()
        end = end.strip()
        start_parts = list(map(int, start.split(".")))
        end_parts = list(map(int, end.split(".")))
        if len(end_parts) == 1:
            end_parts = [start_parts[0], start_parts[1], start_parts[2], end_parts[0]]
        start_int = (
            (start_parts[0] << 24)
            | (start_parts[1] << 16)
            | (start_parts[2] << 8)
            | start_parts[3]
        )
        end_int = (
            (end_parts[0] << 24)
            | (end_parts[1] << 16)
            | (end_parts[2] << 8)
            | end_parts[3]
        )
        results = []
        for i in range(start_int, end_int + 1):
            results.append(self._int_to_ip(i))
        return results[:10000]

    @staticmethod
    def _int_to_ip(i: int) -> str:
        return f"{(i >> 24) & 0xFF}.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"


class PortParser:
    def __init__(self) -> None:
        pass

    def parse(self, port_spec: str) -> list[dict[str, int | str]]:
        ports: list[dict[str, int | str]] = []
        for part in port_spec.split(","):
            part = part.strip()
            if not part:
                continue
            protocol = "tcp"
            if part.startswith("U:"):
                protocol = "udp"
                part = part[2:]
            elif part.startswith("T:"):
                protocol = "tcp"
                part = part[2:]
            elif part.startswith("S:"):
                protocol = "sctp"
                part = part[2:]
            parsed = self._parse_port_or_range(part, protocol)
            ports.extend(parsed)
        return ports

    def _parse_port_or_range(
        self, spec: str, protocol: str = "tcp"
    ) -> list[dict[str, int | str]]:
        if "-" in spec:
            parts = spec.split("-")
            if len(parts) == 2:
                start = self._parse_port(parts[0])
                end = self._parse_port(parts[1])
                if start and end:
                    return [
                        {"port": p, "protocol": protocol, "state": "unknown"}
                        for p in range(start, end + 1)
                        if 0 < p <= 65535
                    ]
            return []
        port = self._parse_port(spec)
        if port:
            return [{"port": port, "protocol": protocol, "state": "unknown"}]
        return []

    def _parse_port(self, port_str: str) -> int | None:
        try:
            port = int(port_str.strip())
            if 0 < port <= 65535:
                return port
        except ValueError:
            pass
        return None
