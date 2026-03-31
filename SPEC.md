# SPEC.md — nmapy

## Purpose

Nmapy is a Python CLI tool that mimics the Nmap (Network Mapper) network scanning utility. It provides network host discovery, port scanning, service detection, OS detection, and script scanning capabilities through a command-line interface compatible with Nmap's usage pattern.

## Scope

### In Scope
- CLI argument parser supporting all Nmap-style options from nmapy.txt
- Target specification parser (hostnames, IP addresses, CIDR notation, ranges)
- Host discovery modes (ping scan, list scan, various discovery probes)
- Port scanning techniques (TCP SYN, Connect, ACK, Window, Maimon, UDP, Null, FIN, Xmas, SCTP, IP Protocol)
- Service/version detection framework
- OS detection framework
- Script scanning framework (NSE-style)
- Timing and performance templates (T0-T5)
- Firewall/IDS evasion options (decoys, spoofing, fragmentation)
- Multiple output formats (Normal, XML, Grepable)
- IPv6 support
- Comprehensive help system

### Not in Scope
- Actual network packet sending/receiving (this is a CLI compatibility layer)
- Real network scanning capabilities
- Integration with actual Nmap binaries

## Public API / Interface

### CLI Interface

**Command Line:**
```
nmapy [Scan Type(s)] [Options] {target specification}
```

**Core Options:**
- `-iL <inputfilename>`: Input from list of hosts/networks
- `-iR <num hosts>`: Choose random targets
- `--exclude <host1[,host2][,host3],...>`: Exclude hosts/networks
- `--excludefile <exclude_file>`: Exclude list from file

**Host Discovery:**
- `-sL`: List Scan - simply list targets to scan
- `-sn`: Ping Scan - disable port scan
- `-Pn`: Treat all hosts as online -- skip host discovery
- `-PS/PA/PU/PY[portlist]`: TCP SYN/ACK/UDP/SCTP discovery
- `-PE/PP/PM`: ICMP echo/timestamp/netmask request probes
- `-PO[protocol list]`: IP Protocol Ping
- `-n/-R`: Never/Always resolve DNS
- `--dns-servers <serv1[,serv2],...>`: Custom DNS servers
- `--system-dns`: Use OS DNS resolver
- `--traceroute`: Trace hop path to each host

**Scan Techniques:**
- `-sS/sT/sA/sW/sM`: TCP SYN/Connect/ACK/Window/Maimon scans
- `-sU`: UDP Scan
- `-sN/sF/sX`: TCP Null, FIN, Xmas scans
- `--scanflags <flags>`: Customize TCP scan flags
- `-sI <zombie host[:probeport]>`: Idle scan
- `-sY/sZ`: SCTP INIT/COOKIE-ECHO scans
- `-sO`: IP protocol scan
- `-b <FTP relay host>`: FTP bounce scan

**Port Specification:**
- `-p <port ranges>`: Scan specified ports
- `--exclude-ports <port ranges>`: Exclude ports
- `-F`: Fast mode
- `-r`: Sequential port scan
- `--top-ports <number>`: Scan most common ports
- `--port-ratio <ratio>`: Scan ports more common than ratio

**Service/Version Detection:**
- `-sV`: Probe open ports for service/version info
- `--version-intensity <level>`: Set intensity (0-9)
- `--version-light`: Limit to likely probes (intensity 2)
- `--version-all`: Try every probe (intensity 9)
- `--version-trace`: Show version scan activity

**Script Scan:**
- `-sC`: Equivalent to --script=default
- `--script=<Lua scripts>`: Run NSE scripts
- `--script-args=<n1=v1,[n2=v2,...]>`: Script arguments
- `--script-args-file=filename`: Script args from file
- `--script-trace`: Show all data sent/received
- `--script-updatedb`: Update script database
- `--script-help=<Lua scripts>`: Show script help

**OS Detection:**
- `-O`: Enable OS detection
- `--osscan-limit`: Limit OS detection to promising targets
- `--osscan-guess`: Guess OS more aggressively

**Timing and Performance:**
- `-T<0-5>`: Timing template (paranoid/sneaky/polite/normal/aggressive/insane)
- `--min-hostgroup/max-hostgroup <size>`: Parallel host scan group sizes
- `--min-parallelism/max-parallelism <numprobes>`: Probe parallelization
- `--min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>`: RTT timeouts
- `--max-retries <tries>`: Probe retransmissions cap
- `--host-timeout <time>`: Give up on target after timeout
- `--scan-delay/--max-scan-delay <time>`: Delay between probes
- `--min-rate/max-rate <number>`: Send packet rate

**Firewall/IDS Evasion:**
- `-f; --mtu <val>`: Fragment packets
- `-D <decoy1,decoy2[,ME],...>`: Cloak scan with decoys
- `-S <IP_Address>`: Spoof source address
- `-e <iface>`: Use specified interface
- `-g/--source-port <portnum>`: Use given port number
- `--proxies <url1,[url2],...>`: Relay through HTTP/SOCKS4 proxies
- `--data <hex string>`: Append custom payload
- `--data-string <string>`: Append custom ASCII string
- `--data-length <num>`: Append random data
- `--ip-options <options>`: Send with IP options
- `--ttl <val>`: Set IP time-to-live
- `--spoof-mac <mac>`: Spoof MAC address
- `--badsum`: Send bogus checksum

**Output:**
- `-oN/-oX/-oS/-oG <file>`: Output in normal/XML/sCript Kiddie/Grepable format
- `-oA <basename>`: Output in all major formats
- `-v/-vv`: Increase verbosity
- `-d/-dd/-ddd`: Increase debugging
- `--reason`: Display reason for port state
- `--open`: Only show open ports
- `--packet-trace`: Show packets sent/received
- `--iflist`: Print host interfaces/routes
- `--append-output`: Append to output files
- `--resume <filename>`: Resume aborted scan
- `--noninteractive`: Disable runtime interactions
- `--stylesheet <path/URL>`: XSL stylesheet for XML to HTML
- `--webxml`: Reference Nmap.org stylesheet
- `--no-stylesheet`: Prevent XSL association

**Misc:**
- `-6`: Enable IPv6 scanning
- `-A`: Enable OS detection, version detection, script scanning, traceroute
- `--datadir <dirname>`: Custom Nmap data file location
- `--send-eth/--send-ip`: Send using raw ethernet/IP
- `--privileged/--unprivileged`: Privilege assumptions
- `-V`: Print version number
- `-h/-?`: Print help summary

### Python API

```python
from nmapy import parse_args, NmapScan, ScanResult

# Parse command-line arguments
args = parse_args(["-sS", "-p", "80", "192.168.1.1"])

# Create and execute scan
scan = NmapScan(args)
result: ScanResult = scan.run()

# Access results
print(result.targets)
print(result.ports)
```

## Data Formats

### Target Specification
- Hostnames: `scanme.nmapy.org`
- IP addresses: `192.168.0.1`
- CIDR notation: `192.168.0.0/24`
- IP ranges: `192.168.0.1-254`
- Combo: `10.0.0-255.1-254`

### Port Specifications
- Single port: `-p22`
- Port range: `-p1-65535`
- Protocol prefixes: `U:53,111,137,T:21-25,80,139,8080,S:9`

### Output Formats
- Normal: Human-readable text
- XML: Machine-parseable XML
- Grepable: Line-based key=value format
- Script Kiddie: Leet speak output

## Edge Cases

1. Empty target list (no hosts specified)
2. Invalid IP addresses or malformed hostnames
3. Invalid port ranges (e.g., 65536-70000)
4. Conflicting options (e.g., -sN with -sT)
5. Non-existent DNS servers
6. File not found for -iL or --excludefile
7. Permission denied for file operations
8. Invalid timing values (negative or excessively large)
9. Invalid script arguments
10. Resume file corruption or incompatible options

## Performance & Constraints

- Target Python version: 3.11+
- Maximum 10000 random targets with -iR
- Port range parsing should handle all valid Nmap formats
- CLI parsing must complete in < 100ms
- No external network dependencies for CLI parsing
- Use only standard library + click/typer for CLI framework