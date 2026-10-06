#!/usr/bin/env python3
"""Runs inside the throwaway VM that tools/capture-e2e.sh boots, as root. Never on a host.

    capture_e2e_guest.py <iohr-capture binary> <result.json>

For each attach mode the kernel offers (netlink always, TCX from Linux 6.6) it:

1. builds a veth pair: veth-cap in the root namespace, veth-peer in namespace `peer`,
   IPv6 off and static neighbour entries, so no background packets (ARP, neighbour discovery, MLD) exist;
2. starts `iohr-capture run --interface veth-cap` and waits for "attached";
3. snapshots veth-cap's own interface counters, sends 1000 UDP datagrams and 100 TCP
   connections (connect, 64 bytes, close) from the peer to a server on veth-cap, waits for
   the server to have all of them, snapshots the counters again, then SIGINTs capture;
4. asserts: capture's ingress/egress packets equal the interface's rx/tx packet deltas
   exactly (both count the same socket buffers, so GRO cannot make them differ), at least
   the traffic sent was seen, the capabilities left match the mode, and no filter or link
   is left on the interface afterwards.

It also checks `doctor` (exit 0 as root, exit 1 without capabilities), and, in netlink
mode, that filters left by a SIGKILLed run are removed by `iohr-capture cleanup`.

How counts are compared: TC sees socket buffers, not wire packets. On a veth pair with
small payloads (no TSO/GSO aggregation, no GRO on veth without XDP) one skb is one packet,
and the interface counters count the same skbs, so the comparison is exact. Bytes are
compared per packet: TC counts skb->len from the Ethernet header; veth's rx/tx bytes count
the same frames, so the difference must be 0 or 14 bytes (Ethernet header) per packet.
"""
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time

UDP_COUNT = 1000
TCP_COUNT = 100
PAYLOAD = 64
CAP_ADDR = "10.203.0.1"
PEER_ADDR = "10.203.0.2"
UDP_PORT = 9999
TCP_PORT = 9998


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
    """UDP and TCP servers on veth-cap's address, counting what arrives."""

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
        self.threads = [threading.Thread(target=self._udp), threading.Thread(target=self._tcp)]
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


def start_capture(binary, mode):
    proc = subprocess.Popen(
        [binary, "run", "--interface", "veth-cap", "--attach", mode],
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
            return proc, log
    proc.kill()
    raise SystemExit(f"capture did not attach ({mode}):\n{''.join(log)}{proc.stdout.read()}")


def leftovers(mode):
    """Filters or links of ours left on veth-cap."""
    out = sh("tc filter show dev veth-cap ingress; tc filter show dev veth-cap egress", check=False).stdout
    left = [l for l in out.splitlines() if "iohr_" in l]
    bpftool = sh("command -v bpftool", check=False).stdout.strip()
    if bpftool and mode == "tcx":
        net = sh(f"{bpftool} net show dev veth-cap", check=False).stdout
        left += [l for l in net.splitlines() if "iohr_" in l]
    return left


def run_mode(binary, mode, version):
    setup()
    servers = Servers()
    proc, log = start_capture(binary, mode)
    before = stats()
    client = sh(f"ip netns exec peer python3 -c '{CLIENT}'", check=False)
    deadline = time.time() + 20
    while time.time() < deadline and (servers.udp_seen < UDP_COUNT or servers.tcp_seen < TCP_COUNT):
        time.sleep(0.1)
    time.sleep(1.0)  # FIN/ACK tails
    after = stats()
    proc.send_signal(signal.SIGINT)
    out, err = proc.communicate(timeout=30)
    servers.close()
    if proc.returncode != 0:
        raise SystemExit(f"capture exited {proc.returncode} ({mode}):\n{''.join(log)}{err}\n{client.stderr}")
    report = json.loads(out)
    delta = {k: after[k] - before[k] for k in after}
    ing, eg = report["ingress"], report["egress"]
    expect_kept = []
    if mode == "netlink":
        expect_kept.append("CAP_NET_ADMIN")
    restricted = open("/proc/sys/kernel/unprivileged_bpf_disabled").read().strip() != "0"
    if version < (6, 5) and restricted:
        expect_kept.insert(0, "CAP_BPF")
    checks = {
        "udp_received": servers.udp_seen == UDP_COUNT,
        "tcp_received": servers.tcp_seen == TCP_COUNT,
        "ingress_packets_equal_rx": ing["packets"] == delta["rx_packets"],
        "egress_packets_equal_tx": eg["packets"] == delta["tx_packets"],
        "ingress_at_least_traffic": ing["packets"] >= UDP_COUNT + 3 * TCP_COUNT,
        "egress_at_least_replies": eg["packets"] >= 2 * TCP_COUNT,
        "ingress_bytes_per_packet": (ing["bytes"] - delta["rx_bytes"]) in (0, 14 * ing["packets"]),
        "egress_bytes_per_packet": (eg["bytes"] - delta["tx_bytes"]) in (0, 14 * eg["packets"]),
        "capabilities_kept": sorted(report["capabilities_after_attach"]["kept"]) == sorted(expect_kept),
        "attach_mode": report["attach"] == mode,
        "detached": report["detached"],
        "nothing_left_on_interface": not leftovers(mode),
    }
    result = {
        "mode": mode,
        "sent": {"udp": UDP_COUNT, "tcp_connections": TCP_COUNT, "payload_bytes": PAYLOAD},
        "interface_delta": delta,
        "capture": {k: report[k] for k in ("ingress", "egress", "packet_unit", "capabilities_after_attach", "seconds")},
        "checks": checks,
    }
    if mode == "netlink":
        result["checks"].update(stale_cleanup(binary))
    sh("ip netns del peer", check=False)
    sh("ip link del veth-cap", check=False)
    return result


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
    out, err = proc.communicate(timeout=30)
    if proc.returncode != 0:
        raise SystemExit(f"capture after a kill exited {proc.returncode}:\n{''.join(log)}{err}")
    removed = json.loads(out).get("stale_filters_removed", 0)
    return {
        "stale_filters_left_by_sigkill": left_after_kill,
        "cleanup_removed_them": cleaned and gone,
        "next_run_removed_stale": removed == 2,
        "nothing_left_after_cleanup_run": not leftovers("netlink"),
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
    version = kernel_version()
    modes = ["netlink"] + (["tcx"] if version >= (6, 6) else [])
    results = {"kernel": os.uname().release, "modes": [], "doctor": doctor(binary)}
    for mode in modes:
        results["modes"].append(run_mode(binary, mode, version))
    ok = results["doctor"]["doctor_root_exit_0"] and results["doctor"]["doctor_unprivileged_exit_1"]
    ok = ok and all(all(m["checks"].values()) for m in results["modes"])
    results["ok"] = ok
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps(results, indent=2))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
