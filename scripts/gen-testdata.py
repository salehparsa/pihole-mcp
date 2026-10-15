#!/usr/bin/env python3
"""Generate the SANITIZED, deterministic fixtures in testdata/.

All identities are fake: documentation IPs (192.0.2.0/24), documentation MACs
(00:00:5e:00:53:xx), made-up hostnames and example domains. Never put real
network data in testdata/.
"""
import json, os, random

random.seed(7)
OUT = os.path.join(os.path.dirname(__file__), "..", "testdata")
T0 = 1760000000  # fixed "now" used by tests

def w(name, obj):
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.write("\n")

clients = [
    ("192.0.2.10", "living-room-tv", "ExampleTV Inc", "00:00:5e:00:53:10", 1),
    ("192.0.2.11", "alice-laptop", "Example Computers", "00:00:5e:00:53:11", 1),
    ("192.0.2.12", "kids-tablet", "Example Mobile", "00:00:5e:00:53:12", 1),
    ("192.0.2.13", "smart-fridge", "Example Appliances", "00:00:5e:00:53:13", 1),
    ("192.0.2.14", "old-camera", "Example Cameras", "00:00:5e:00:53:14", 0),
]
allowed = [("example.com", 30), ("github.com", 20), ("cdn.example.net", 25),
           ("api.example-cloud.com", 15), ("ads.example-tracker.net", 14),
           ("metrics.example-analytics.com", 12), ("nxdomain.example.org", 3)]
blocked = [("ads.example-ads.com", 40), ("pixel.example-track.net", 25),
           ("telemetry.smart-fridge.example", 30), ("adserver.example.org", 20),
           ("tracker.example-tracker.net", 10)]
weights = {"192.0.2.10": (0.35, 5), "192.0.2.11": (0.1, 40), "192.0.2.12": (0.7, 25),
           "192.0.2.13": (0.9, 20), "192.0.2.14": (0.0, 0)}

def pick(pairs):
    tot = sum(p[1] for p in pairs); r = random.uniform(0, tot)
    for d, wt in pairs:
        r -= wt
        if r <= 0: return d
    return pairs[-1][0]

qs = []
qid = 1
for ip, name, *_ in clients:
    ratio, n = weights[ip]
    for _ in range(n * 4):
        is_blocked = random.random() < ratio
        dom = pick(blocked if is_blocked else allowed)
        t = T0 - random.randint(60, 80000)
        status = ("GRAVITY" if random.random() < 0.9 else "DENYLIST") if is_blocked else \
                 ("CACHE" if random.random() < 0.4 else "FORWARDED")
        if dom.startswith("nxdomain"):
            reply = "NXDOMAIN"
        else:
            reply = "NODATA" if is_blocked and False else "IP"
        qs.append({"time": t + random.random(), "type": "A", "domain": dom, "status": status,
                   "client": {"ip": ip, "name": name}, "dnssec": "UNKNOWN",
                   "upstream": None if (is_blocked or status == "CACHE") else "192.0.2.53#53",
                   "reply": {"type": reply, "time": round(random.random() * 20, 2)},
                   "list_id": 1 if (is_blocked and status == "GRAVITY") else None, "cname": None})
qs.sort(key=lambda q: -q["time"])  # Pi-hole returns newest first
for i, q in enumerate(qs):
    q["id"] = len(qs) - i
w("queries.json", {"queries": qs})

w("clients.json", {"clients": [
    {"client": ip, "name": name, "comment": None, "groups": [0], "id": i + 1}
    for i, (ip, name, *_) in enumerate(clients)]})
w("devices.json", {"devices": [
    {"id": i + 1, "hwaddr": mac, "interface": "eth0", "firstSeen": T0 - 86400 * 90,
     "lastQuery": (T0 - 120) if active else (T0 - 86400 * 20),
     "numQueries": (500 if active else 3), "macVendor": vendor,
     "ips": [{"ip": ip, "name": name, "lastSeen": T0 - 100, "nameUpdated": T0 - 1000}]}
    for i, (ip, name, vendor, mac, active) in enumerate(clients)]})

DAY = 86400
w("lists.json", {"lists": [
    {"id": 1, "address": "https://lists.example.org/pro.txt", "type": "block", "comment": "Main list", "groups": [0], "enabled": True,
     "date_added": T0 - 90 * DAY, "date_modified": T0 - 90 * DAY, "date_updated": T0 - 1 * DAY, "number": 150000, "invalid_domains": 12, "abp_entries": 0, "status": 1},
    {"id": 2, "address": "https://lists.example.org/stale.txt", "type": "block", "comment": "Old list", "groups": [0], "enabled": True,
     "date_added": T0 - 200 * DAY, "date_modified": T0 - 200 * DAY, "date_updated": T0 - 30 * DAY, "number": 20000, "invalid_domains": 0, "abp_entries": 0, "status": 2},
    {"id": 3, "address": "https://lists.example.org/broken.txt", "type": "block", "comment": "Dead URL", "groups": [0], "enabled": True,
     "date_added": T0 - 100 * DAY, "date_modified": T0 - 100 * DAY, "date_updated": T0 - 40 * DAY, "number": 0, "invalid_domains": 0, "abp_entries": 0, "status": 3},
    {"id": 4, "address": "https://lists.example.org/disabled.txt", "type": "block", "comment": "Turned off", "groups": [0], "enabled": False,
     "date_added": T0 - 100 * DAY, "date_modified": T0 - 50 * DAY, "date_updated": T0 - 50 * DAY, "number": 5000, "invalid_domains": 0, "abp_entries": 0, "status": 1},
    {"id": 5, "address": "https://lists.example.org/messy.txt", "type": "block", "comment": "Many invalid", "groups": [0], "enabled": True,
     "date_added": T0 - 60 * DAY, "date_modified": T0 - 60 * DAY, "date_updated": T0 - 2 * DAY, "number": 1000, "invalid_domains": 800, "abp_entries": 0, "status": 1},
]})
w("domains.json", {"domains": [
    {"id": 1, "domain": "ads.example-tracker.net", "unicode": "ads.example-tracker.net", "type": "allow", "kind": "exact", "comment": "needed by app", "groups": [0], "enabled": True, "date_added": T0 - 10 * DAY, "date_modified": T0 - 10 * DAY},
    {"id": 2, "domain": ".*", "unicode": ".*", "type": "allow", "kind": "regex", "comment": "oops", "groups": [0], "enabled": True, "date_added": T0 - 5 * DAY, "date_modified": T0 - 5 * DAY},
    {"id": 3, "domain": "(\\.|^)example-ads\\.com$", "unicode": "", "type": "deny", "kind": "regex", "comment": "", "groups": [0], "enabled": True, "date_added": T0 - 5 * DAY, "date_modified": T0 - 5 * DAY},
]})
w("summary.json", {"queries": {"total": len(qs), "blocked": sum(1 for q in qs if q["status"] in ("GRAVITY", "DENYLIST")),
    "percent_blocked": 0, "unique_domains": 12, "forwarded": 100, "cached": 50, "frequency": 0.1,
    "types": {"A": len(qs)}, "status": {}, "replies": {}},
    "clients": {"active": 4, "total": 5}, "gravity": {"domains_being_blocked": 176000, "last_update": T0 - DAY}})
w("upstreams.json", {"upstreams": [
    {"ip": "192.0.2.53", "name": None, "port": 53, "count": 100, "statistics": {"response": 0.02, "variance": 0.001}}],
    "forwarded_queries": 100, "total_queries": 200})
w("history.json", {"history": [{"timestamp": T0 - 3600 * (10 - i) + 0.5, "total": 20 + i, "cached": 5, "blocked": 4 + i, "forwarded": 10} for i in range(10)]})
w("info_version.json", {"version": {"core": {"local": {"version": "v6.4.3"}, "remote": {"version": "v6.4.3"}},
    "web": {"local": {"version": "v6.4"}, "remote": {"version": "v6.4"}},
    "ftl": {"local": {"version": "v6.7.1"}, "remote": {"version": "v6.8"}},
    "docker": {"local": "2025.10.0", "remote": "2025.10.0"}}})
w("info_system.json", {"system": {"uptime": 864000, "memory": {"ram": {"total": 4000000, "used": 1000000, "%used": 25.0}, "swap": {"total": 100000, "used": 0, "%used": 0.0}},
    "procs": 120, "cpu": {"nprocs": 4, "load": {"raw": [0.2, 0.3, 0.3], "percent": [5.0, 7.5, 7.5]}, "%cpu": 5.0}, "ftl": {"%mem": 1.2, "%cpu": 0.5}}})
w("info_sensors.json", {"sensors": {"cpu_temp": 52.3, "hot_limit": 80.0, "unit": "C"}})
w("info_host.json", {"host": {"uname": {"domainname": "(none)", "machine": "aarch64", "nodename": "pihole-test", "release": "6.1", "sysname": "Linux", "version": "#1"}}})
w("info_database.json", {"size": 150000000, "queries": 900000, "sqlite_version": "3.46.0"})
w("info_ftl.json", {"ftl": {"database": {"gravity": 176000, "groups": 1, "lists": 5, "clients": 5, "domains": {"allowed": {"total": 2, "enabled": 2}, "denied": {"total": 1, "enabled": 1}}},
    "privacy_level": 0, "query_frequency": 0.1, "%mem": 1.2, "%cpu": 0.5, "pid": 123, "uptime": 864000}})
w("info_messages.json", {"messages": [
    {"id": 1, "type": "DNSMASQ_WARN", "plain": "dnsmasq: warning example", "html": "dnsmasq: warning example", "timestamp": T0 - 3600 + 0.25}]})
w("blocking.json", {"blocking": "enabled", "timer": None})
print("wrote", len(qs), "queries")
