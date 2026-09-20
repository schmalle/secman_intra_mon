# Scanner tools

`secman-intra-mon` wraps external scanner binaries instead of reimplementing
them. Each adapter in `src/secman_intra_mon/scanners/` builds an argument list,
runs the binary with `shell=False` and a mandatory timeout, and parses stdout.
Binaries are never bundled — install them via your OS packages or use the
[Docker image](DOCKER.md), which contains the full set.

| Tool | Purpose | Phases used in | Privileges needed | Required? |
| --- | --- | --- | --- | --- |
| nmap | host discovery + service/version scan | discovery (fallback), service scan (always) | none for `-sn`/`-sV`; root or `CAP_NET_RAW` for `-PR` and `-O` | **yes** |
| fping | fast ICMP sweep | discovery (preferred on routed networks) | typically setuid/`CAP_NET_RAW` from the OS package; none from our side | no |
| arp-scan | layer-2 ARP sweep with MAC vendors | discovery (L2-adjacent networks only) | root or `CAP_NET_RAW` | no |
| masscan | very fast open-port pre-scan | `masscan` profile only | root or `CAP_NET_RAW` | no |
| traceroute | router hops for expansion | expansion | none | no |

## nmap (required)

The primary scanner, used in every run.

- Host discovery fallback: `nmap -sn -n -T4 --max-retries 2 [-PR] -oX - <targets>`
  (`-PR` ARP ping when the network is L2-adjacent and we are raw-capable;
  reported as `nmap-pr`, otherwise `nmap-sn`).
- Service scan: `nmap -sV --version-intensity 4 -n -T4 -Pn [ports] [-O]
  --host-timeout 300s -oX - <targets>` where ports come from the profile
  (`fast` = `--top-ports 100`, `default` = `--top-ports 1000`, `full` = `-p-`)
  or from `--ports/-p` on the `scan` command.
- Live targets are split into batches of 256 to stay below operating-system
  argument limits. `-Pn` is intentional: a target already seen by ARP, fping,
  or nmap discovery must not disappear merely because it blocks nmap's second
  discovery check.
- The raw `-oX` XML is parsed with stdlib `xml.etree.ElementTree` (no DTDs or
  external entities) and retained in memory so `--upload-secman` can submit the
  genuine nmap output to the backend.

nmap is the only hard requirement because every profile ends in an `nmap -sV`
service scan, and nmap is also the final host-discovery fallback when neither
arp-scan nor fping applies or is installed. Without nmap the tool refuses to
scan (`required tool 'nmap' not found in PATH`).

## fping (optional)

`fping -a -q -r 1 -g <network>` — only hosts that answer are printed (`-a`),
one retry. Exit code 1 ("no host answered") is treated as a valid empty
result. Preferred for routed (non-L2) networks because it is much faster than
nmap's ping scan on large ranges.

## arp-scan (optional, root)

`arp-scan [--interface <iface>] --retry 2 <network>` — the most reliable
discovery on a directly connected segment: ARP cannot be filtered by a host
firewall the way ICMP can, and it yields MAC addresses plus vendors for free.
It works only at layer 2 — never across routers — so it is selected only when
the target network exactly matches one of the host's interface networks and we
hold `CAP_NET_RAW`. `(DUP: n)` lines are folded into the first sighting.

## masscan (optional, root)

`masscan <network> -p 1-10000 --rate <pps> --open-only -oX -` — used only by
`--profile masscan`. masscan finds open ports across the whole network
quickly; its `-oX` output is a compatible subset of nmap's and parsed by the
same parser. Every host/port is then re-verified with `nmap -sV`, grouped by
identical port-set to keep nmap invocations few, so service names and versions
always come from nmap. The rate defaults to 1000 packets/second
(`--masscan-rate`) — deliberately moderate for intranet use; raise it only on
networks you control. Hosts found solely through open ports are added with
`discovered_via` = `masscan`.

## traceroute (optional)

`traceroute -n -q1 -w2 -m8 <host>` — one probe per hop, 2 s wait, max 8 hops.
Hop addresses outside the traced host's own subnet are router interfaces and
become expansion candidates. A failing traceroute is not an error: it simply
contributes no candidates, and without the binary there is no expansion.

## Runtime capability detection

There is no configuration for tool selection — the engine probes `PATH` at
startup (`<tool> --version` / `fping -v`) and checks privileges by reading
`CapEff` from `/proc/self/status` on Linux (falling back to euid elsewhere).
Inspect the verdict before scanning:

```bash
uv run secman-intra-mon capabilities
```

The output lists each tool with its path and version, whether we run as root,
and whether `CAP_NET_RAW` is held, so you can tell upfront which discovery
paths and profiles are actually usable.

## Fallback chains at a glance

```
host discovery (L2-adjacent + CAP_NET_RAW):  union(arp-scan, fping, nmap -sn -PR)
host discovery (routed):                     union(fping, nmap -sn)
service scan:                                nmap -sV            (always)
masscan profile:                             masscan → nmap -sV verification
expansion:                                   traceroute → (none; skipped if absent)
```

The union is deliberate: ICMP-only discovery misses filtered hosts, while
nmap's mixed probes and layer-2 ARP find different populations. A failed
optional method does not discard results from another method. IPv6 uses nmap;
the packaged `arp-scan`, `fping`, and masscan paths are treated as IPv4-only.
