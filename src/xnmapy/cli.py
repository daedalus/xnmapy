import click

from xnmapy._core import NmapScan, ScanOptions


@click.command(
    context_settings={"ignore_unknown_options": True},
    add_help_option=False,
)
@click.argument("targets", nargs=-1, required=False)
@click.option(
    "-iL", "--input-list", "input_list", help="Input from list of hosts/networks"
)
@click.option(
    "-iR", "--random-hosts", "random_hosts", type=int, help="Choose random targets"
)
@click.option(
    "--exclude",
    "exclude_hosts",
    help="Exclude hosts/networks (comma-separated)",
)
@click.option(
    "--excludefile",
    "exclude_file",
    help="Exclude list from file",
)
@click.option("-sL", "list_scan", is_flag=True, help="List Scan - simply list targets")
@click.option("-sn", "ping_scan", is_flag=True, help="Ping Scan - disable port scan")
@click.option("-Pn", "skip_discovery", is_flag=True, help="Treat all hosts as online")
@click.option("-PS", "tcp_syn_discovery", help="TCP SYN discovery")
@click.option("-PA", "tcp_ack_discovery", help="TCP ACK discovery")
@click.option("-PU", "udp_discovery", help="UDP discovery")
@click.option("-PY", "sctp_discovery", help="SCTP discovery")
@click.option("-PE", "icmp_echo", is_flag=True, help="ICMP echo discovery")
@click.option("-PP", "icmp_timestamp", is_flag=True, help="ICMP timestamp discovery")
@click.option("-PM", "icmp_netmask", is_flag=True, help="ICMP netmask discovery")
@click.option("-PO", "ip_protocol_ping", help="IP Protocol Ping")
@click.option("-n", "no_dns", is_flag=True, help="Never do DNS resolution")
@click.option("-R", "always_dns", is_flag=True, help="Always resolve DNS")
@click.option("--dns-servers", "dns_servers", help="Specify custom DNS servers")
@click.option("--system-dns", "system_dns", is_flag=True, help="Use OS DNS resolver")
@click.option("--traceroute", "traceroute", is_flag=True, help="Trace hop path")
@click.option("-sS", "tcp_syn_scan", is_flag=True, help="TCP SYN scan")
@click.option("-sT", "tcp_connect_scan", is_flag=True, help="TCP Connect scan")
@click.option("-sA", "tcp_ack_scan", is_flag=True, help="TCP ACK scan")
@click.option("-sW", "tcp_window_scan", is_flag=True, help="TCP Window scan")
@click.option("-sM", "tcp_maimon_scan", is_flag=True, help="TCP Maimon scan")
@click.option("-sU", "udp_scan", is_flag=True, help="UDP scan")
@click.option("-sN", "tcp_null_scan", is_flag=True, help="TCP Null scan")
@click.option("-sF", "tcp_fin_scan", is_flag=True, help="TCP FIN scan")
@click.option("-sX", "tcp_xmas_scan", is_flag=True, help="TCP Xmas scan")
@click.option("--scanflags", "scanflags", help="Customize TCP scan flags")
@click.option("-sI", "idle_scan", help="Idle scan")
@click.option("-sY", "sctp_init_scan", is_flag=True, help="SCTP INIT scan")
@click.option(
    "-sZ", "sctp_cookie_echo_scan", is_flag=True, help="SCTP COOKIE-ECHO scan"
)
@click.option("-sO", "ip_protocol_scan", is_flag=True, help="IP protocol scan")
@click.option("-b", "ftp_bounce", help="FTP bounce scan")
@click.option("-p", "ports", help="Scan specified ports")
@click.option("--exclude-ports", "exclude_ports", help="Exclude ports from scanning")
@click.option("-F", "fast_scan", is_flag=True, help="Fast mode - scan fewer ports")
@click.option("-r", "sequential_ports", is_flag=True, help="Scan ports sequentially")
@click.option("--top-ports", "top_ports", type=int, help="Scan top N most common ports")
@click.option(
    "--port-ratio", "port_ratio", type=float, help="Scan ports more common than ratio"
)
@click.option(
    "-sV", "version_detection", is_flag=True, help="Probe open ports for version info"
)
@click.option(
    "--version-intensity",
    "version_intensity",
    type=int,
    help="Set version detection intensity (0-9)",
)
@click.option(
    "--version-light", "version_light", is_flag=True, help="Limit to most likely probes"
)
@click.option(
    "--version-all", "version_all", is_flag=True, help="Try every single probe"
)
@click.option(
    "--version-trace", "version_trace", is_flag=True, help="Show version scan activity"
)
@click.option("-sC", "script_scan", is_flag=True, help="Run default scripts")
@click.option("--script", "scripts", help="NSE scripts (comma-separated)")
@click.option("--script-args", "script_args", help="NSE script arguments")
@click.option(
    "--script-args-file", "script_args_file", help="NSE script args from file"
)
@click.option(
    "--script-trace",
    "script_trace",
    is_flag=True,
    help="Show script data sent/received",
)
@click.option(
    "--script-updatedb", "script_updatedb", is_flag=True, help="Update script database"
)
@click.option("--script-help", "script_help", help="Show help about scripts")
@click.option("-O", "os_detection", is_flag=True, help="Enable OS detection")
@click.option(
    "--osscan-limit", "os_scan_limit", is_flag=True, help="Limit OS detection"
)
@click.option(
    "--osscan-guess", "os_scan_guess", is_flag=True, help="Guess OS more aggressively"
)
@click.option(
    "-T",
    "timing",
    type=click.Choice(["0", "1", "2", "3", "4", "5"]),
    help="Timing template",
)
@click.option(
    "--min-hostgroup",
    "min_hostgroup",
    type=int,
    help="Min parallel host scan group size",
)
@click.option(
    "--max-hostgroup",
    "max_hostgroup",
    type=int,
    help="Max parallel host scan group size",
)
@click.option(
    "--min-parallelism", "min_parallelism", type=int, help="Min probe parallelization"
)
@click.option(
    "--max-parallelism", "max_parallelism", type=int, help="Max probe parallelization"
)
@click.option("--min-rtt-timeout", "min_rtt_timeout", help="Min RTT timeout")
@click.option("--max-rtt-timeout", "max_rtt_timeout", help="Max RTT timeout")
@click.option(
    "--initial-rtt-timeout", "initial_rtt_timeout", help="Initial RTT timeout"
)
@click.option(
    "--max-retries", "max_retries", type=int, help="Max port scan probe retransmissions"
)
@click.option(
    "--host-timeout", "host_timeout", help="Give up on target after this long"
)
@click.option("--scan-delay", "scan_delay", help="Delay between probes")
@click.option("--max-scan-delay", "max_scan_delay", help="Max delay between probes")
@click.option(
    "--min-rate", "min_rate", type=int, help="Send packets no slower than N per second"
)
@click.option(
    "--max-rate", "max_rate", type=int, help="Send packets no faster than N per second"
)
@click.option("-f", "fragment", is_flag=True, help="Fragment packets")
@click.option("--mtu", "mtu", type=int, help="Fragment packets with given MTU")
@click.option("-D", "decoys", help="Cloak scan with decoys")
@click.option("-S", "spoof_source", help="Spoof source address")
@click.option("-e", "interface", help="Use specified interface")
@click.option("-g", "source_port", type=int, help="Use given port number")
@click.option("--source-port", "source_port", type=int, help="Use given port number")
@click.option("--proxies", "proxies", help="Relay through HTTP/SOCKS4 proxies")
@click.option("--data", "data", help="Append custom hex payload")
@click.option("--data-string", "data_string", help="Append custom ASCII string")
@click.option("--data-length", "data_length", type=int, help="Append random data")
@click.option("--ip-options", "ip_options", help="Send packets with IP options")
@click.option("--ttl", "ttl", type=int, help="Set IP time-to-live")
@click.option("--spoof-mac", "spoof_mac", help="Spoof MAC address")
@click.option("--badsum", "badsum", is_flag=True, help="Send bogus checksum")
@click.option("-oN", "output_normal", help="Output in normal format")
@click.option("-oX", "output_xml", help="Output in XML format")
@click.option("-oS", "output_script_kiddie", help="Output in script kiddie format")
@click.option("-oG", "output_grepable", help="Output in grepable format")
@click.option("-oA", "output_all", help="Output in all major formats")
@click.option("-v", "verbose", count=True, help="Increase verbosity")
@click.option("-d", "debug", count=True, help="Increase debugging")
@click.option("--reason", "reason", is_flag=True, help="Display reason for port state")
@click.option("--open", "show_open", is_flag=True, help="Only show open ports")
@click.option(
    "--packet-trace", "packet_trace", is_flag=True, help="Show packets sent/received"
)
@click.option("--iflist", "iflist", is_flag=True, help="Print host interfaces")
@click.option(
    "--append-output", "append_output", is_flag=True, help="Append to output files"
)
@click.option("--resume", "resume", help="Resume an aborted scan")
@click.option(
    "--noninteractive",
    "noninteractive",
    is_flag=True,
    help="Disable runtime interactions",
)
@click.option("--stylesheet", "stylesheet", help="XSL stylesheet for XML")
@click.option("--webxml", "webxml", is_flag=True, help="Reference Nmap.org stylesheet")
@click.option(
    "--no-stylesheet", "no_stylesheet", is_flag=True, help="Prevent XSL association"
)
@click.option("-6", "ipv6", is_flag=True, help="Enable IPv6 scanning")
@click.option(
    "-A",
    "aggressive",
    is_flag=True,
    help="Enable OS detection, version, script, traceroute",
)
@click.option("--datadir", "datadir", help="Custom Nmap data file location")
@click.option(
    "--send-eth", "send_eth", is_flag=True, help="Send using raw ethernet frames"
)
@click.option("--send-ip", "send_ip", is_flag=True, help="Send using IP packets")
@click.option(
    "--privileged", "privileged", is_flag=True, help="Assume fully privileged"
)
@click.option(
    "--unprivileged",
    "unprivileged",
    is_flag=True,
    help="Assume lacks raw socket privileges",
)
@click.option("-V", "version", is_flag=True, help="Print version number")
@click.option("-h", "help", is_flag=True, help="Print help summary")
@click.option("-?", "help2", is_flag=True, help="Print help summary")
def main(
    targets: tuple[str, ...],
    input_list: str | None,
    random_hosts: int | None,
    exclude_hosts: str | None,
    exclude_file: str | None,
    list_scan: bool,
    ping_scan: bool,
    skip_discovery: bool,
    tcp_syn_discovery: str | None,
    tcp_ack_discovery: str | None,
    udp_discovery: str | None,
    sctp_discovery: str | None,
    icmp_echo: bool,
    icmp_timestamp: bool,
    icmp_netmask: bool,
    ip_protocol_ping: str | None,
    no_dns: bool,
    always_dns: bool,
    dns_servers: str | None,
    system_dns: bool,
    traceroute: bool,
    tcp_syn_scan: bool,
    tcp_connect_scan: bool,
    tcp_ack_scan: bool,
    tcp_window_scan: bool,
    tcp_maimon_scan: bool,
    udp_scan: bool,
    tcp_null_scan: bool,
    tcp_fin_scan: bool,
    tcp_xmas_scan: bool,
    scanflags: str | None,
    idle_scan: str | None,
    sctp_init_scan: bool,
    sctp_cookie_echo_scan: bool,
    ip_protocol_scan: bool,
    ftp_bounce: str | None,
    ports: str | None,
    exclude_ports: str | None,
    fast_scan: bool,
    sequential_ports: bool,
    top_ports: int | None,
    port_ratio: float | None,
    version_detection: bool,
    version_intensity: int | None,
    version_light: bool,
    version_all: bool,
    version_trace: bool,
    script_scan: bool,
    scripts: str | None,
    script_args: str | None,
    script_args_file: str | None,
    script_trace: bool,
    script_updatedb: bool,
    script_help: str | None,
    os_detection: bool,
    os_scan_limit: bool,
    os_scan_guess: bool,
    timing: str | None,
    min_hostgroup: int | None,
    max_hostgroup: int | None,
    min_parallelism: int | None,
    max_parallelism: int | None,
    min_rtt_timeout: str | None,
    max_rtt_timeout: str | None,
    initial_rtt_timeout: str | None,
    max_retries: int | None,
    host_timeout: str | None,
    scan_delay: str | None,
    max_scan_delay: str | None,
    min_rate: int | None,
    max_rate: int | None,
    fragment: bool,
    mtu: int | None,
    decoys: str | None,
    spoof_source: str | None,
    interface: str | None,
    source_port: int | None,
    proxies: str | None,
    data: str | None,
    data_string: str | None,
    data_length: int | None,
    ip_options: str | None,
    ttl: int | None,
    spoof_mac: str | None,
    badsum: bool,
    output_normal: str | None,
    output_xml: str | None,
    output_script_kiddie: str | None,
    output_grepable: str | None,
    output_all: str | None,
    verbose: int,
    debug: int,
    reason: bool,
    show_open: bool,
    packet_trace: bool,
    iflist: bool,
    append_output: bool,
    resume: str | None,
    noninteractive: bool,
    stylesheet: str | None,
    webxml: bool,
    no_stylesheet: bool,
    ipv6: bool,
    aggressive: bool,
    datadir: str | None,
    send_eth: bool,
    send_ip: bool,
    privileged: bool,
    unprivileged: bool,
    version: bool,
    help: bool,
    help2: bool,
) -> int:
    """Xnmapy - Network Mapper Clone"""
    if version:
        click.echo("Xnmapy version 0.1.0")
        return 0
    if help or help2:
        print_help()
        return 0
    iflist_func(iflist)
    if not targets and not input_list and not random_hosts:
        click.echo("Error: No targets specified.", err=True)
        print_help()
        return 1
    scan_options = ScanOptions(
        targets=list(targets) if targets else [],
        input_list=input_list,
        random_hosts=random_hosts,
        exclude_hosts=exclude_hosts,
        exclude_file=exclude_file,
        list_scan=list_scan,
        ping_scan=ping_scan,
        skip_discovery=skip_discovery,
        tcp_syn_discovery=tcp_syn_discovery,
        tcp_ack_discovery=tcp_ack_discovery,
        udp_discovery=udp_discovery,
        sctp_discovery=sctp_discovery,
        icmp_echo=icmp_echo,
        icmp_timestamp=icmp_timestamp,
        icmp_netmask=icmp_netmask,
        ip_protocol_ping=ip_protocol_ping,
        no_dns=no_dns,
        always_dns=always_dns,
        dns_servers=dns_servers,
        system_dns=system_dns,
        traceroute=traceroute,
        scan_type=_determine_scan_type(
            tcp_syn_scan,
            tcp_connect_scan,
            tcp_ack_scan,
            tcp_window_scan,
            tcp_maimon_scan,
            udp_scan,
            tcp_null_scan,
            tcp_fin_scan,
            tcp_xmas_scan,
            sctp_init_scan,
            sctp_cookie_echo_scan,
            ip_protocol_scan,
            ftp_bounce,
            idle_scan,
            scanflags,
        ),
        ports=ports,
        exclude_ports=exclude_ports,
        fast_scan=fast_scan,
        sequential_ports=sequential_ports,
        top_ports=top_ports,
        port_ratio=port_ratio,
        version_detection=version_detection,
        version_intensity=version_intensity
        if version_intensity
        else (2 if version_light else (9 if version_all else 4)),
        version_trace=version_trace,
        script_scan=script_scan,
        scripts=scripts,
        script_args=script_args,
        script_args_file=script_args_file,
        script_trace=script_trace,
        script_updatedb=script_updatedb,
        script_help=script_help,
        os_detection=os_detection or aggressive,
        os_scan_limit=os_scan_limit,
        os_scan_guess=os_scan_guess,
        timing=timing,
        min_hostgroup=min_hostgroup,
        max_hostgroup=max_hostgroup,
        min_parallelism=min_parallelism,
        max_parallelism=max_parallelism,
        min_rtt_timeout=min_rtt_timeout,
        max_rtt_timeout=max_rtt_timeout,
        initial_rtt_timeout=initial_rtt_timeout,
        max_retries=max_retries,
        host_timeout=host_timeout,
        scan_delay=scan_delay,
        max_scan_delay=max_scan_delay,
        min_rate=min_rate,
        max_rate=max_rate,
        fragment=fragment,
        mtu=mtu,
        decoys=decoys,
        spoof_source=spoof_source,
        interface=interface,
        source_port=source_port,
        proxies=proxies,
        data=data,
        data_string=data_string,
        data_length=data_length,
        ip_options=ip_options,
        ttl=ttl,
        spoof_mac=spoof_mac,
        badsum=badsum,
        output_normal=output_normal,
        output_xml=output_xml,
        output_script_kiddie=output_script_kiddie,
        output_grepable=output_grepable,
        output_all=output_all,
        verbose=verbose,
        debug=debug,
        reason=reason,
        show_open=show_open,
        packet_trace=packet_trace,
        append_output=append_output,
        resume=resume,
        noninteractive=noninteractive,
        stylesheet=stylesheet,
        webxml=webxml,
        no_stylesheet=no_stylesheet,
        ipv6=ipv6,
        aggressive=aggressive,
        datadir=datadir,
        send_eth=send_eth,
        send_ip=send_ip,
        privileged=privileged,
        unprivileged=unprivileged,
    )
    scan = NmapScan(scan_options)
    result = scan.run()
    click.echo(
        f"Scan completed: {len(result.targets)} targets, {len(result.ports)} ports"
    )
    return 0


def _determine_scan_type(
    tcp_syn: bool,
    tcp_conn: bool,
    tcp_ack: bool,
    tcp_win: bool,
    tcp_maimon: bool,
    udp: bool,
    tcp_null: bool,
    tcp_fin: bool,
    tcp_xmas: bool,
    sctp_init: bool,
    sctp_echo: bool,
    ip_proto: bool,
    ftp_bounce: str | None,
    idle: str | None,
    scanflags: str | None,
) -> str | None:
    if tcp_syn:
        return "SYN"
    if tcp_conn:
        return "CONNECT"
    if tcp_ack:
        return "ACK"
    if tcp_win:
        return "WINDOW"
    if tcp_maimon:
        return "MAIMON"
    if udp:
        return "UDP"
    if tcp_null:
        return "NULL"
    if tcp_fin:
        return "FIN"
    if tcp_xmas:
        return "XMAS"
    if sctp_init:
        return "SCTP_INIT"
    if sctp_echo:
        return "SCTP_COOKIE_ECHO"
    if ip_proto:
        return "IP_PROTOCOL"
    if ftp_bounce:
        return "BOUNCE"
    if idle:
        return "IDLE"
    if scanflags:
        return "CUSTOM"
    return None


def iflist_func(iflist: bool) -> None:
    if iflist:
        click.echo("Interface List:")
        click.echo("  eth0: 192.168.1.0/24")
        click.echo("  lo: 127.0.0.1/8")


def print_help() -> None:
    click.echo("""Xnmapy - Network Mapper Clone
Usage: xnmapy [Scan Type(s)] [Options] {target specification}

TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.xnmapy.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks
  -iR <num hosts>: Choose random targets
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
  --excludefile <exclude_file>: Exclude list from file

HOST DISCOVERY:
  -sL: List Scan
  -sn: Ping Scan
  -Pn: Treat all hosts as online
  -PS/PA/PU/PY[portlist]: TCP SYN/ACK/UDP/SCTP discovery
  -PE/PP/PM: ICMP echo/timestamp/netmask request
  -PO[protocol list]: IP Protocol Ping
  -n/-R: Never/Always resolve DNS
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OS DNS resolver
  --traceroute: Trace hop path

SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect/ACK/Window/Maimon
  -sU: UDP Scan
  -sN/sF/sX: TCP Null/FIN/Xmas
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan

PORT SPECIFICATION:
  -p <port ranges>: Scan specified ports
  -F: Fast mode
  -r: Sequential scan
  --top-ports <number>: Scan most common ports
  --port-ratio <ratio>: Scan ports more common than ratio

SERVICE/VERSION DETECTION:
  -sV: Probe open ports for version info
  --version-intensity <level>: Set intensity 0-9
  --version-light: Limit to likely probes
  --version-all: Try every probe

SCRIPT SCAN:
  -sC: Run default scripts
  --script=<Lua scripts>: Run NSE scripts
  --script-args=<n1=v1,...>: Script arguments

OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit to promising targets
  --osscan-guess: Guess OS more aggressively

TIMING AND PERFORMANCE:
  -T<0-5>: Timing template (paranoid/sneaky/polite/normal/aggressive/insane)
  --min-hostgroup/max-hostgroup <size>: Parallel host scan sizes
  --max-retries <tries>: Probe retransmissions
  --host-timeout <time>: Give up on target
  --min-rate/max-rate <number>: Send rate

FIREWALL/IDS EVASION:
  -f: Fragment packets
  --mtu <val>: Fragment with MTU
  -D <decoy1,decoy2,...>: Cloak with decoys
  -S <IP>: Spoof source address
  -e <iface>: Use interface
  -g/--source-port <port>: Use port
  --spoof-mac <mac>: Spoof MAC address

OUTPUT:
  -oN/-oX/-oS/-oG <file>: Normal/XML/sCript/Grepable
  -oA <basename>: All major formats
  -v: Increase verbosity
  -d: Increase debugging

MISC:
  -6: Enable IPv6
  -A: Aggressive (OS+version+script+traceroute)
  -V: Print version
  -h: Print help

EXAMPLES:
  xnmapy -v -A scanme.xnmapy.org
  xnmapy -v -sn 192.168.0.0/16
  xnmapy -v -iR 10000 -Pn -p 80""")
