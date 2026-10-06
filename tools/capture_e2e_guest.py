#!/usr/bin/env python3
"""Runs inside the throwaway VM that tools/capture-e2e.sh boots, as root. Never on a host.

    capture_e2e_guest.py <iohr-capture binary> <result.json>

For each attach mode the kernel offers (netlink always, TCX from Linux 6.6) it:

1. builds a veth pair: veth-cap in the root namespace, veth-peer in namespace `peer`,
   IPv6 off and static neighbour entries, so no background packets exist;
2. starts servers on veth-cap's address: UDP and TCP counters (phase 0), an HTTP/1 server
   in its own cgroup (`/sys/fs/cgroup/iohr-e2e-web`, for the owner check), a TLS server
   (openssl s_server), a DNS responder, an HTTP/2 cleartext server for h2c and gRPC calls,
   a listener that never accepts (listen queue overflow) and one that holds a connection
   open (RTT sample);
3. starts `iohr-capture run --interface veth-cap` with its sockets in a scratch directory;
4. snapshots veth-cap's counters, sends from the peer: 1000 UDP datagrams, 100 TCP
   connections, N HTTP/1 requests with a Host, N TLS handshakes with a known SNI, N DNS
   queries for one known name, N gRPC calls and N h2c requests, connections to a closed
   port (resets), connections into the full listen queue; snapshots the counters again;
5. asks the aggregates socket (`iohr-capture stats --tables --json`), checks the socket's
   access rules (SO_PEERCRED) and the control socket, then SIGINTs capture;
6. asserts per layer:
   - headers: capture's ingress/egress skb counts equal the interface's rx/tx deltas
     exactly (both count the same socket buffers), resets counted on the closed port;
   - protocols: exact counts of HTTP/1 requests and responses, TLS hellos with the SNI,
     DNS queries for the name, h2c connections, gRPC calls and method;
   - owners: flows to the HTTP/1 port attributed to the cgroup and `python3`;
   - tcp: the held connection's RTT sampled, the listen overflow seen;
   - no drops at this rate; privileges dropped before parsing; nothing left on the
     interface afterwards.

Then a flood (UDP to 40000 distinct ports) with a 4 KiB ring buffer and a 512-flow table
proves drops are counted (ring buffer full, flows evicted) while totals stay exact and
memory bounded, and a second flood with a 100/s rate limit proves rate-limited copies are
counted. It also checks `doctor` (exit 0 as root, exit 1 without capabilities), and, in
netlink mode, that filters left by a SIGKILLed run are removed by `iohr-capture cleanup`.
"""
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

UDP_COUNT = 1000
TCP_COUNT = 100
PAYLOAD = 64
N_HTTP = 20
N_TLS = 10
N_DNS = 15
N_GRPC = 5
N_H2 = 5
N_RST = 5
N_OVERFLOW = 8
CAP_ADDR = "10.203.0.1"
PEER_ADDR = "10.203.0.2"
UDP_PORT = 9999
TCP_PORT = 9998
HTTP_PORT = 8080
TLS_PORT = 8443
DNS_PORT = 53
H2_PORT = 50051
CLOSED_PORT = 9
FULL_PORT = 7777
HOLD_PORT = 7000
HOST = "web.e2e.test"
SNI = "tls-e2e.example"
QNAME = "same.dns-e2e.example"
GRPC_METHOD = "/e2e.Echo/Say"
CGROUP = "/sys/fs/cgroup/iohr-e2e-web"
SCRATCH = "/tmp/iohr-e2e"


def sh(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)


def kernel_version():
    m = re.match(r"(\d+)\.(\d+)", os.uname().release)
    return int(m.group(1)), int(m.group(2))


def setup():
    sh("ip netns del peer", check=False)
    sh("ip link del veth-cap", check=False)
    sh("ip netns add peer")
    sh("ip link add veth-cap type veth peer name veth-peer")
    sh("ip link set veth-peer netns peer")
    sh("sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1")
    sh("ip netns exec peer sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1")
    sh(f"ip addr add {CAP_ADDR}/24 dev veth-cap")
    sh(f"ip netns exec peer ip addr add {PEER_ADDR}/24 dev veth-peer")
    sh("ip link set veth-cap up")
    sh("ip netns exec peer ip link set veth-peer up")
    sh("ip netns exec peer ip link set lo up")
    cap_mac = open("/sys/class/net/veth-cap/address").read().strip()
    peer_mac = sh("ip netns exec peer cat /sys/class/net/veth-peer/address").stdout.strip()
    sh(f"ip neigh replace {PEER_ADDR} lladdr {peer_mac} dev veth-cap nud permanent")
    sh(f"ip netns exec peer ip neigh replace {CAP_ADDR} lladdr {cap_mac} dev veth-peer nud permanent")
    time.sleep(1.0)  # let link-up settle before counting starts


def stats():
    base = "/sys/class/net/veth-cap/statistics/"
    return {k: int(open(base + k).read()) for k in ("rx_packets", "rx_bytes", "tx_packets", "tx_bytes")}


class Servers:
    """UDP and TCP servers on veth-cap's address, counting what arrives (phase 0)."""

    def __init__(self):
        self.udp_seen = 0
        self.tcp_seen = 0
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.udp.bind((CAP_ADDR, UDP_PORT))
        self.udp.settimeout(0.2)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((CAP_ADDR, TCP_PORT))
        self.tcp.listen(256)
        self.tcp.settimeout(0.2)
        self.stop = False
        self.threads = [threading.Thread(target=self._udp, daemon=True), threading.Thread(target=self._tcp, daemon=True)]
        for t in self.threads:
            t.start()

    def _udp(self):
        while not self.stop:
            try:
                self.udp.recv(2048)
                self.udp_seen += 1
            except socket.timeout:
                pass

    def _tcp(self):
        while not self.stop:
            try:
                conn, _ = self.tcp.accept()
            except socket.timeout:
                continue
            with conn:
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if len(data) == PAYLOAD:
                    self.tcp_seen += 1

    def close(self):
        self.stop = True
        for t in self.threads:
            t.join()
        self.udp.close()
        self.tcp.close()


class Protocols:
    """The phase 1 servers: HTTP/1 (own cgroup), TLS, DNS, h2c, a full listen queue and a
    held connection."""

    def __init__(self):
        self.procs = []
        self.stop = False
        os.makedirs(SCRATCH, exist_ok=True)
        os.makedirs(CGROUP, exist_ok=True)
        # The server moves itself into the cgroup before it creates its socket, so the
        # listener and every accepted socket belong to that cgroup.
        self.procs.append(subprocess.Popen(
            ["sh", "-c", f"echo $$ > {CGROUP}/cgroup.procs && exec python3 -m http.server {HTTP_PORT} --bind {CAP_ADDR} --directory {SCRATCH}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        sh(f"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN={SNI} "
           f"-keyout {SCRATCH}/key.pem -out {SCRATCH}/cert.pem")
        self.procs.append(subprocess.Popen(
            ["openssl", "s_server", "-quiet", "-accept", f"{CAP_ADDR}:{TLS_PORT}", "-cert", f"{SCRATCH}/cert.pem",
             "-key", f"{SCRATCH}/key.pem", "-alpn", "h2,http/1.1", "-www"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        self.dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns.bind((CAP_ADDR, DNS_PORT))
        self.dns.settimeout(0.2)
        self.h2 = self._listener(H2_PORT, 64)
        self.full = self._listener(FULL_PORT, 1)  # never accepted
        self.hold = self._listener(HOLD_PORT, 4)
        self.held = []
        self.threads = [threading.Thread(target=f, daemon=True) for f in (self._dns, self._h2, self._hold)]
        for t in self.threads:
            t.start()
        for _ in range(50):
            if all(port_open(p) for p in (HTTP_PORT, TLS_PORT)):
                break
            time.sleep(0.1)

    @staticmethod
    def _listener(port, backlog):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((CAP_ADDR, port))
        s.listen(backlog)
        s.settimeout(0.2)
        return s

    def _dns(self):
        while not self.stop:
            try:
                q, addr = self.dns.recvfrom(2048)
            except socket.timeout:
                continue
            # NXDOMAIN: the question echoed, QR set, rcode 3.
            r = bytearray(q)
            r[2] |= 0x80
            r[3] = (r[3] & 0xF0) | 3
            self.dns.sendto(bytes(r), addr)

    def _h2(self):
        while not self.stop:
            try:
                c, _ = self.h2.accept()
            except socket.timeout:
                continue
            threading.Thread(target=h2_conversation, args=(c,), daemon=True).start()

    def _hold(self):
        while not self.stop:
            try:
                c, _ = self.hold.accept()
                self.held.append(c)
            except socket.timeout:
                continue

    def close(self):
        self.stop = True
        for t in self.threads:
            t.join()
        for p in self.procs:
            p.kill()
            p.wait()
        for s in [self.dns, self.h2, self.full, self.hold] + self.held:
            s.close()


def port_open(port):
    try:
        socket.create_connection((CAP_ADDR, port), timeout=0.2).close()
        return True
    except OSError:
        return False


def h2_conversation(c):
    """A minimal HTTP/2 server: SETTINGS, read the request, answer :status 200."""
    c.settimeout(3)
    try:
        c.sendall(struct.pack(">I", 0)[1:] + bytes([4, 0]) + struct.pack(">I", 0))
        buf = b""
        while True:
            chunk = c.recv(4096)
            if not chunk:
                return
            buf += chunk
            frames = buf[24:]
            ended = False
            while len(frames) >= 9:
                length = int.from_bytes(frames[:3], "big")
                kind, flags = frames[3], frames[4]
                if kind in (0, 1) and flags & 0x1:
                    ended = True
                frames = frames[9 + length:]
            if ended:
                break
        # SETTINGS ack, then HEADERS (:status 200, indexed 0x88) with END_STREAM|END_HEADERS.
        c.sendall(bytes([0, 0, 0, 4, 1, 0, 0, 0, 0]))
        c.sendall(bytes([0, 0, 1, 1, 5, 0, 0, 0, 1, 0x88]))
        time.sleep(0.1)
    except OSError:
        pass
    finally:
        c.close()


CLIENT = f"""
import socket, time
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range({UDP_COUNT}):
    u.sendto(b"u" * {PAYLOAD}, ("{CAP_ADDR}", {UDP_PORT}))
    if i % 50 == 49:
        time.sleep(0.005)
for i in range({TCP_COUNT}):
    s = socket.create_connection(("{CAP_ADDR}", {TCP_PORT}))
    s.sendall(b"t" * {PAYLOAD})
    s.close()
"""

# Connections to a closed port (each answered by a RST) and into a listener whose queue is
# full (overflows); a held connection that keeps sending (an RTT sample).
SIDE = f"""
import socket, time, threading
for i in range({N_RST}):
    try:
        socket.create_connection(("{CAP_ADDR}", {CLOSED_PORT}), timeout=1).close()
    except OSError:
        pass
full = []
for i in range({N_OVERFLOW}):
    s = socket.socket()
    s.setblocking(False)
    try:
        s.connect(("{CAP_ADDR}", {FULL_PORT}))
    except BlockingIOError:
        pass
    full.append(s)
time.sleep(2)
"""

HOLD = f"""
import socket, time
s = socket.create_connection(("{CAP_ADDR}", {HOLD_PORT}))
for i in range(400):
    s.sendall(b"x")
    time.sleep(0.05)
"""


def peer(cmd, timeout=60):
    return subprocess.run(["ip", "netns", "exec", "peer"] + cmd, capture_output=True, text=True, timeout=timeout)


def generate():
    """The phase 1 traffic, from the peer namespace. Returns what each tool reported."""
    out = {"curl_http1_ok": 0, "tls_ok": 0, "dig_ok": 0, "grpc_sent": 0, "h2_sent": 0}
    for i in range(N_HTTP):
        r = peer(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-H", f"Host: {HOST}",
                  f"http://{CAP_ADDR}:{HTTP_PORT}/items/{1000 + i}?token=secret-{i}"])
        out["curl_http1_ok"] += r.stdout.strip() in ("200", "404")
    for _ in range(N_TLS):
        r = peer(["sh", "-c", f"echo | timeout 5 openssl s_client -connect {CAP_ADDR}:{TLS_PORT} -servername {SNI} -alpn h2,http/1.1 -verify_quiet"])
        out["tls_ok"] += "CONNECTED" in r.stdout
    for _ in range(N_DNS):
        r = peer(["dig", f"@{CAP_ADDR}", QNAME, "A", "+tries=1", "+time=2", "+noedns"])
        out["dig_ok"] += "NXDOMAIN" in r.stdout
    for _ in range(N_GRPC):
        peer(["curl", "-s", "-m", "3", "--http2-prior-knowledge", "-X", "POST", "-H", "content-type: application/grpc",
              "-H", "te: trailers", "--data-binary", "x", f"http://{CAP_ADDR}:{H2_PORT}{GRPC_METHOD}"])
        out["grpc_sent"] += 1
    for _ in range(N_H2):
        peer(["curl", "-s", "-m", "3", "--http2-prior-knowledge", f"http://{CAP_ADDR}:{H2_PORT}/h2/items/7"])
        out["h2_sent"] += 1
    peer(["python3", "-c", SIDE])
    return out


def start_capture(binary, mode, extra=()):
    shutil.rmtree(f"{SCRATCH}/sock", ignore_errors=True)
    proc = subprocess.Popen(
        [binary, "run", "--interface", "veth-cap", "--attach", mode, "--poll-ms", "500",
         "--aggregates-socket", f"{SCRATCH}/sock/aggregates.sock", "--control-socket", f"{SCRATCH}/sock/control.sock",
         "--socket-group", "nogroup", "--agent-user", "nobody", *extra],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.time() + 30
    log = []
    while time.time() < deadline:
        line = proc.stderr.readline()
        if not line:
            break
        log.append(line)
        if "attached" in line:
            # Keep draining stderr so a chatty run never blocks on a full pipe.
            threading.Thread(target=lambda: log.extend(proc.stderr), daemon=True).start()
            return proc, log
    proc.kill()
    raise SystemExit(f"capture did not attach ({mode}):\n{''.join(log)}{proc.stdout.read()}")


def stop_capture(proc, log, what):
    proc.send_signal(signal.SIGINT)
    out, _ = proc.communicate(timeout=30)
    if proc.returncode != 0:
        raise SystemExit(f"capture exited {proc.returncode} ({what}):\n{''.join(log)}")
    return json.loads(out)


def query(binary, tables=True, user=None):
    cmd = [binary, "stats", "--socket", f"{SCRATCH}/sock/aggregates.sock", "--json"] + (["--tables"] if tables else [])
    if user:
        cmd = ["setpriv", f"--reuid={user[0]}", f"--regid={user[1]}"] + user[2] + ["--inh-caps=-all", "--bounding-set=-all"] + cmd
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    try:
        return json.loads(r.stdout), r
    except json.JSONDecodeError:
        return None, r


def control(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    s.sendall(b'{"version": 1, "request": "pcap"}\n')
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return json.loads(data)


def leftovers(mode):
    """Filters or links of ours left on veth-cap."""
    out = sh("tc filter show dev veth-cap ingress; tc filter show dev veth-cap egress", check=False).stdout
    left = [l for l in out.splitlines() if "iohr_" in l]
    bpftool = sh("command -v bpftool", check=False).stdout.strip()
    if bpftool and mode == "tcx":
        net = sh(f"{bpftool} net show dev veth-cap", check=False).stdout
        left += [l for l in net.splitlines() if "iohr_" in l]
    return left


def top(rows, key):
    return next((r["count"] for r in rows if r["key"] == key), 0)


def expected_kept(mode, version):
    kept = []
    if mode == "netlink":
        kept.append("CAP_NET_ADMIN")
    restricted = open("/proc/sys/kernel/unprivileged_bpf_disabled").read().strip() != "0"
    if version < (6, 5) and restricted:
        kept.insert(0, "CAP_BPF")
    return kept


def run_mode(binary, mode, version):
    setup()
    servers = Servers()
    protos = Protocols()
    proc, log = start_capture(binary, mode)
    hold = subprocess.Popen(["ip", "netns", "exec", "peer", "python3", "-c", HOLD])
    before = stats()
    client = sh(f"ip netns exec peer python3 -c '{CLIENT}'", check=False)
    tools = generate()
    deadline = time.time() + 20
    while time.time() < deadline and (servers.udp_seen < UDP_COUNT or servers.tcp_seen < TCP_COUNT):
        time.sleep(0.1)
    time.sleep(2.0)  # FIN/ACK tails and two polls of the maps and sockets
    snap, raw = query(binary)
    counts_only, _ = query(binary, tables=False)
    as_group, _ = query(binary, tables=False, user=("65534", "65534", ["--clear-groups"]))
    as_other, other_raw = query(binary, tables=False, user=("2", "2", ["--groups=65534"]))
    # nobody is the agent's user here: counts yes, tables never (the companion enforces it).
    agent_tables, agent_tables_raw = query(binary, tables=True, user=("65534", "65534", ["--clear-groups"]))
    parser = parser_caps(proc.pid)
    ctl = control(f"{SCRATCH}/sock/control.sock")
    agg_mode = oct(os.stat(f"{SCRATCH}/sock/aggregates.sock").st_mode & 0o777)
    ctl_mode = oct(os.stat(f"{SCRATCH}/sock/control.sock").st_mode & 0o777)
    hold.kill()
    hold.wait()
    after = stats()
    report = stop_capture(proc, log, mode)
    servers.close()
    protos.close()
    if snap is None:
        raise SystemExit(f"no answer from the aggregates socket ({mode}): {raw.stderr}\n{''.join(log)}")
    delta = {k: after[k] - before[k] for k in after}
    ing, eg = report["ingress"], report["egress"]
    t = snap["tables"]
    p = snap["protocols"]
    owner = next((o for o in t["owners"] if o["owner"] == "cgroup:/iohr-e2e-web"), {})
    port9 = sum(r["rst"] for r in t["ports"] if r["port"] == CLOSED_PORT and r["proto"] == "tcp")
    hold_row = next((r for r in t["tcp_ports"] if r["port"] == HOLD_PORT), {})
    rtt_samples = sum(snap["tcp"]["rtt_ms"].values())
    checks = {
        # layer 1, exact against the interface (phase 0)
        "udp_received": servers.udp_seen == UDP_COUNT,
        "tcp_received": servers.tcp_seen == TCP_COUNT,
        "ingress_packets_equal_rx": ing["packets"] == delta["rx_packets"],
        "egress_packets_equal_tx": eg["packets"] == delta["tx_packets"],
        "ingress_at_least_traffic": ing["packets"] >= UDP_COUNT + 3 * TCP_COUNT,
        "egress_at_least_replies": eg["packets"] >= 2 * TCP_COUNT,
        "ingress_bytes_per_packet": (ing["bytes"] - delta["rx_bytes"]) in (0, 14 * ing["packets"]),
        "egress_bytes_per_packet": (eg["bytes"] - delta["tx_bytes"]) in (0, 14 * eg["packets"]),
        "resets_counted_on_the_closed_port": port9 >= N_RST and snap["tcp"]["resets_out"] >= N_RST,
        "udp_class_counted": snap["headers"]["classes"]["udp4"]["ingress"]["packets"] >= UDP_COUNT,
        # layer 2, exact
        "tools_succeeded": tools["curl_http1_ok"] == N_HTTP and tools["tls_ok"] == N_TLS and tools["dig_ok"] == N_DNS,
        "http1_requests": p["http1_requests"] == N_HTTP,
        "http1_responses": p["http1_responses"] == N_HTTP,
        "http1_host": top(t["http1"]["hosts"], HOST) == N_HTTP,
        "http1_path_template": top(t["http1"]["paths"], "GET /items/{id}") == N_HTTP,
        "tls_hellos": p["tls_client_hellos"] == N_TLS,
        "tls_sni": top(t["tls"]["sni"], SNI) == N_TLS,
        "dns_queries": p["dns_queries"] == N_DNS and p["dns_responses"] == N_DNS,
        "dns_name": top(t["dns"]["names"], QNAME) == N_DNS,
        "http2_connections": p["http2_connections"] == N_GRPC + N_H2,
        "grpc_calls": p["grpc_calls"] == N_GRPC and top(t["http2"]["grpc_methods"], GRPC_METHOD) == N_GRPC,
        "h2_path": top(t["http2"]["paths"], "GET /h2/items/{id}") == N_H2,
        "no_secrets_in_tables": "secret-" not in json.dumps(snap),
        # layer 4
        "owner_cgroup_and_process": owner.get("process") == "python3" and HTTP_PORT in owner.get("listening_ports", []),
        "owner_flows": owner.get("flows", 0) >= N_HTTP,
        # layer 5
        "rtt_sampled": rtt_samples >= 1 and hold_row.get("established", 0) >= 1,
        "listen_overflow_seen": snap["tcp"]["host"]["listen_overflows"] >= 1,
        # bounds and drops at this rate
        "no_copy_drops": snap["drops"]["rate_limited"] == 0 and snap["drops"]["ring_buffer_full"] == 0,
        # privileges and sockets
        "parser_process_has_no_capabilities": snap["privileges"]["parser_capabilities"] == []
        and parser.get("CapEff") == "0000000000000000" and parser.get("CapPrm") == "0000000000000000",
        "companion_kept_reported": sorted(snap["privileges"]["companion_kept"]) == sorted(expected_kept(mode, version)),
        "agent_user_gets_no_tables": agent_tables is None and "forbidden" in agent_tables_raw.stderr,
        "capabilities_kept": sorted(report["capabilities_after_attach"]["kept"]) == sorted(expected_kept(mode, version)),
        "counts_answer_has_no_tables": counts_only is not None and "tables" not in counts_only,
        "socket_modes": agg_mode == "0o660" and ctl_mode == "0o600",
        "group_member_may_read": as_group is not None and "error" not in as_group,
        "peer_check_refuses_others": as_other is None and "forbidden" in other_raw.stderr,
        "control_not_available": ctl.get("error") == "not_available",
        "attach_mode": report["attach"] == mode,
        "detached": report["detached"],
        "nothing_left_on_interface": not leftovers(mode),
        "sockets_removed": not os.path.exists(f"{SCRATCH}/sock/aggregates.sock"),
    }
    result = {
        "mode": mode,
        "sent": {"udp": UDP_COUNT, "tcp_connections": TCP_COUNT, "http1": N_HTTP, "tls": N_TLS, "dns": N_DNS,
                 "grpc": N_GRPC, "h2c": N_H2, "resets": N_RST, "overflow_attempts": N_OVERFLOW},
        "tools": tools,
        "interface_delta": delta,
        "capture": {k: report[k] for k in ("ingress", "egress", "packet_unit", "capabilities_after_attach", "seconds")},
        "layers": {
            "headers": {"classes_udp4_in": snap["headers"]["classes"]["udp4"]["ingress"]["packets"],
                        "tcp_flags": snap["headers"]["tcp_flags"], "closed_port_rst": port9},
            "protocols": p,
            "owners": {"summary": snap["owners"], "web": owner},
            "tcp": {k: snap["tcp"][k] for k in ("established", "listening", "retransmits_sampled", "rtt_ms", "resets_in", "resets_out", "host")},
            "flows": snap["flows"],
            "drops": snap["drops"],
            "memory": snap["memory"],
        },
        "checks": checks,
        "client_stderr": client.stderr[-2000:],
    }
    if mode == "netlink":
        result["checks"].update(stale_cleanup(binary))
    sh("ip netns del peer", check=False)
    sh("ip link del veth-cap", check=False)
    return result


FLOOD = f"""
import socket
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(40000):
    u.sendto(b"f" * 32, ("{CAP_ADDR}", 20000 + i))
"""


DNS_AFTER = f"""
import socket
q = bytes.fromhex("12340100000100000000000005616674657205666c6f6f64076578616d706c650000010001")
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(5):
    u.sendto(q, ("{CAP_ADDR}", 53))
"""


def parser_caps(parent_pid):
    """CapEff and CapPrm of the parser process (the `worker` child of `run`)."""
    kids = sh(f"pgrep -P {parent_pid}", check=False).stdout.split()
    for k in kids:
        try:
            status = open(f"/proc/{k}/status").read()
            if "worker" in open(f"/proc/{k}/cmdline").read():
                return dict(l.split(":\t", 1) for l in status.splitlines() if l.startswith("Cap"))
        except OSError:
            pass
    return {}


def rss_kib(pid):
    try:
        for l in open(f"/proc/{pid}/status"):
            if l.startswith("VmRSS:"):
                return int(l.split()[1])
    except OSError:
        pass
    return -1


def flood(binary, mode, extra):
    """A flood of new UDP flows: totals stay exact, drops are counted, memory bounded, and
    layer 2 keeps working afterwards (5 DNS queries after the flood must be counted)."""
    setup()
    proc, log = start_capture(binary, mode, extra)
    before = stats()
    peer(["python3", "-c", FLOOD], timeout=120)
    time.sleep(1.5)
    peer(["python3", "-c", DNS_AFTER])
    time.sleep(1.5)
    after = stats()
    parent_rss = rss_kib(proc.pid)
    snap, raw = query(binary, tables=False)
    report = stop_capture(proc, log, "flood")
    sh("ip netns del peer", check=False)
    sh("ip link del veth-cap", check=False)
    if snap is None:
        raise SystemExit(f"no answer during the flood: {raw.stderr}")
    delta = {k: after[k] - before[k] for k in after}
    return {
        "extra": list(extra),
        "ingress_packets": report["ingress"]["packets"],
        "rx_delta": delta["rx_packets"],
        "drops": snap["drops"],
        "flows": snap["flows"],
        "copy": snap["copy"],
        "memory": snap["memory"],
        "parent_rss_kib": parent_rss,
        "dns_after_flood": snap["protocols"]["dns_queries"],
        "totals_exact": report["ingress"]["packets"] == delta["rx_packets"],
    }


def stale_cleanup(binary):
    """A SIGKILLed netlink run leaves its filters; `cleanup` and the next run remove them."""
    proc, _ = start_capture(binary, "netlink")
    proc.kill()
    proc.wait()
    left_after_kill = bool(leftovers("netlink"))
    cleaned = sh(f"{binary} cleanup --interface veth-cap", check=False).returncode == 0
    gone = not leftovers("netlink")
    # And a fresh run after another kill reports the stale filters it removed.
    proc, _ = start_capture(binary, "netlink")
    proc.kill()
    proc.wait()
    proc, log = start_capture(binary, "netlink")
    proc.send_signal(signal.SIGINT)
    out, _ = proc.communicate(timeout=30)
    if proc.returncode != 0:
        raise SystemExit(f"capture after a kill exited {proc.returncode}:\n{''.join(log)}")
    removed = json.loads(out).get("stale_filters_removed", 0)
    return {
        "stale_filters_left_by_sigkill": left_after_kill,
        "cleanup_removed_them": cleaned and gone,
        "next_run_removed_stale": removed == 2,
        "nothing_left_after_cleanup_run": not leftovers("netlink"),
    }


def free_ids(path, count, start=64900):
    used = {int(l.split(":")[2]) for l in open(path) if l.count(":") >= 3 and l.split(":")[2].isdigit()}
    out, n = [], start
    while len(out) < count:
        if n not in used:
            out.append(n)
        n += 1
    return out


def unit_test(binary):
    """The shipped unit (packaging/systemd/iohr-capture.service), started by a real systemd:
    systemd runs as PID 1 of a new PID namespace inside the VM, with the guest's throwaway
    /etc and /usr. Proves the unit's sandbox (system call filter, RestrictSUIDSGID, the
    runtime directory, Group=) lets iohr-capture start and serve, and the socket's access
    rules: a member of iohr-capture-read reads the tables, the agent's user reads counts
    only, anyone else is kept out by the directory's mode. Runs last: systemd stays up
    until the VM ends."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    g_read, g_cap, g_agent, g_reader = free_ids("/etc/group", 4)
    u_cap, u_agent, u_reader = free_ids("/etc/passwd", 3, start=g_reader + 1)
    # The guest's /etc is an overlay; groupadd cannot read the host's gshadow, so append.
    with open("/etc/group", "a") as f:
        f.write(f"iohr-capture-read:x:{g_read}:iohr-agent,e2e-reader\niohr-capture:x:{g_cap}:\n"
                f"iohr-agent:x:{g_agent}:\ne2e-reader:x:{g_reader}:\n")
    with open("/etc/passwd", "a") as f:
        f.write(f"iohr-capture:x:{u_cap}:{g_cap}::/nonexistent:/usr/sbin/nologin\n"
                f"iohr-agent:x:{u_agent}:{g_agent}::/nonexistent:/usr/sbin/nologin\n"
                f"e2e-reader:x:{u_reader}:{g_reader}::/nonexistent:/usr/sbin/nologin\n")
    shutil.copy(binary, "/usr/bin/iohr-capture")
    os.makedirs("/etc/iohr-capture", exist_ok=True)
    with open("/etc/iohr-capture/capture.env", "w") as f:
        f.write("IOHR_CAPTURE_INTERFACE=lo\nIOHR_CAPTURE_POLL_MS=500\n")
    shutil.copy(os.path.join(repo, "packaging/systemd/iohr-capture.service"), "/etc/systemd/system/")
    with open("/etc/systemd/system/iohr-e2e.target", "w") as f:
        f.write("[Unit]\nDescription=iohr-capture e2e\nRequires=iohr-capture.service\nAfter=iohr-capture.service\n")
    sh("ip link set lo up", check=False)
    web = subprocess.Popen(["python3", "-m", "http.server", "18080", "--bind", "127.0.0.1", "--directory", SCRATCH],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    systemd = subprocess.Popen(["unshare", "--pid", "--fork", "--mount-proc", "/usr/lib/systemd/systemd", "--system",
                                "--unit=iohr-e2e.target", "--log-target=kmsg"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = ""
    for _ in range(50):
        pid = sh(f"pgrep -P {systemd.pid}", check=False).stdout.split()
        if pid:
            pid = pid[0]
            break
        time.sleep(0.2)
    ns = f"nsenter -t {pid} -m -p"
    up = False
    for _ in range(240):
        if sh(f"{ns} test -S /run/iohr-capture/aggregates.sock", check=False).returncode == 0:
            up = True
            break
        time.sleep(0.5)
    time.sleep(1.0)
    for i in range(3):
        sh(f"curl -s -o /dev/null -H 'Host: unit.e2e.test' http://127.0.0.1:18080/u/{i}", check=False)
    time.sleep(2.0)

    def stats_as(uid, gid, groups, tables):
        cmd = (f"{ns} setpriv --reuid={uid} --regid={gid} --groups={groups} --inh-caps=-all --bounding-set=-all "
               f"/usr/bin/iohr-capture stats --json" + (" --tables" if tables else ""))
        r = sh(cmd, check=False)
        try:
            return json.loads(r.stdout), r.stderr
        except json.JSONDecodeError:
            return None, r.stderr

    reader, _ = stats_as(u_reader, g_reader, g_read, True)
    agent_counts, _ = stats_as(u_agent, g_agent, g_read, False)
    agent_tables, agent_err = stats_as(u_agent, g_agent, g_read, True)
    outsider, outsider_err = stats_as(65534, 65534, 65534, False)
    dir_stat = sh(f"{ns} stat -c '%a %G %U' /run/iohr-capture", check=False).stdout.strip()
    sock_stat = sh(f"{ns} stat -c '%a %G' /run/iohr-capture/aggregates.sock", check=False).stdout.strip()
    journal = sh(f"{ns} journalctl -u iohr-capture --no-pager", check=False).stdout
    restarts = sh("dmesg", check=False).stdout.count("iohr-capture.service: Scheduled restart")
    main_pid = sh("pgrep -f '^/usr/bin/iohr-capture run'", check=False).stdout.split()
    parser = parser_caps(main_pid[0]) if main_pid else {}
    web.kill()
    hosts = reader["tables"]["http1"]["hosts"] if reader else []
    checks = {
        "unit_started_and_serves": up and reader is not None,
        "no_failure_no_restart": "capture failed" not in journal and restarts == 0,
        "runtime_dir_setgid_read_group": dir_stat == "2750 iohr-capture-read iohr-capture",
        "socket_0660_read_group": sock_stat == "660 iohr-capture-read",
        "reader_gets_tables": top(hosts, "unit.e2e.test") >= 3,
        "agent_gets_counts": agent_counts is not None and "tables" not in agent_counts,
        "agent_gets_no_tables": agent_tables is None and "forbidden" in agent_err,
        "others_kept_out": outsider is None,
        "parser_has_no_capabilities": parser.get("CapEff") == "0000000000000000",
    }
    return {
        "checks": checks,
        "dir": dir_stat,
        "socket": sock_stat,
        "http1_requests_on_lo": (reader or {}).get("protocols", {}).get("http1_requests"),
        "companion_kept": (reader or {}).get("privileges", {}).get("companion_kept"),
        "journal_tail": journal[-3000:],
        "outsider_error": outsider_err[-300:],
    }



def doctor(binary):
    sh("ip link add veth-doc type veth peer name veth-doc2", check=False)
    as_root = sh(f"{binary} doctor --interface veth-doc", check=False)
    as_nobody = sh(
        f"setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all {binary} doctor --interface veth-doc",
        check=False,
    )
    sh("ip link del veth-doc", check=False)
    return {
        "doctor_root_exit_0": as_root.returncode == 0,
        "doctor_unprivileged_exit_1": as_nobody.returncode == 1 and "FAIL  capabilities" in as_nobody.stdout,
        "doctor_root_output": as_root.stdout,
    }


def main():
    if "virtme" not in open("/proc/cmdline").read() or os.getuid() != 0:
        raise SystemExit("refusing: this test runs only as root inside the virtme-ng VM (mise run capture:e2e)")
    binary, out_path = sys.argv[1], sys.argv[2]
    if not os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
        sh("mount -t cgroup2 none /sys/fs/cgroup", check=False)
    os.makedirs(SCRATCH, exist_ok=True)
    version = kernel_version()
    modes = ["netlink"] + (["tcx"] if version >= (6, 6) else [])
    results = {"kernel": os.uname().release, "modes": [], "doctor": doctor(binary)}
    for mode in modes:
        results["modes"].append(run_mode(binary, mode, version))
    small = flood(binary, "auto", ["--ring-buffer-kib", "4", "--max-flows", "512", "--samples-per-sec", "0"])
    limited = flood(binary, "auto", ["--samples-per-sec", "100", "--burst", "10"])
    # A large ring and no rate limit: the reader must keep up and never stall.
    unlimited = flood(binary, "auto", ["--samples-per-sec", "0", "--ring-buffer-kib", "16384"])
    results["flood"] = {
        "small_ring": small,
        "rate_limited": limited,
        "unlimited": unlimited,
        "checks": {
            "layer2_alive_after_unlimited_flood": unlimited["dns_after_flood"] == 5,
            "reader_caught_up": unlimited["copy"]["records_read"] == unlimited["copy"]["records_copied"],
            "totals_exact_under_flood": small["totals_exact"] and limited["totals_exact"],
            "ring_buffer_full_counted": small["drops"]["ring_buffer_full"] > 0,
            "flows_evicted_counted": small["flows"]["evicted"] > 0 and small["flows"]["active"] <= 512,
            "rate_limited_counted": limited["drops"]["rate_limited"] > 0,
            "memory_bounded": max(f[k] if k == "parent_rss_kib" else f["memory"]["rss_kib"]
                                  for f in (small, limited, unlimited) for k in ("parent_rss_kib", "memory")) < 64 * 1024,
        },
    }
    ok = results["doctor"]["doctor_root_exit_0"] and results["doctor"]["doctor_unprivileged_exit_1"]
    ok = ok and all(all(m["checks"].values()) for m in results["modes"])
    ok = ok and all(results["flood"]["checks"].values())
    results["unit"] = unit_test(binary)
    ok = ok and all(results["unit"]["checks"].values())
    results["ok"] = ok
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps(results, indent=2))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
