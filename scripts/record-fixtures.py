#!/usr/bin/env python3
"""Record SANITIZED fixtures from a live Pi-hole using read-only GET requests.

Environment: PIHOLE_URL, PIHOLE_APP_PASSWORD. Output: testdata/recorded/*.json
(git-ignored). Review the files before copying anything into testdata/.

Only GET requests are made (plus the login/logout of the API session). Identifying
data is replaced: IPv4 -> 192.0.2.x, IPv6 -> 2001:db8::x, MACs -> 00:00:5e:00:53:xx,
host names -> host-N, and queried domains -> site-N.example unless they are on
a block list entry that looks generic. No query log is written unless
RECORD_QUERIES=1 (it is the most privacy-sensitive file).
"""
import json, os, re, sys, urllib.request, urllib.error

base = os.environ.get("PIHOLE_URL", "").rstrip("/")
pw = os.environ.get("PIHOLE_APP_PASSWORD", "")
if not base or not pw:
    sys.exit("set PIHOLE_URL and PIHOLE_APP_PASSWORD")
out_dir = os.path.join(os.path.dirname(__file__), "..", "testdata", "recorded")
os.makedirs(out_dir, exist_ok=True)

def req(method, path, body=None, sid=None):
    r = urllib.request.Request(base + "/api" + path, method=method,
                               data=json.dumps(body).encode() if body is not None else None,
                               headers={"Content-Type": "application/json", **({"X-FTL-SID": sid} if sid else {})})
    with urllib.request.urlopen(r, timeout=30) as resp:
        data = resp.read()
        return json.loads(data) if data else None

maps = {"ip4": {}, "ip6": {}, "mac": {}, "host": {}, "dom": {}}
def m(kind, key, fmt):
    d = maps[kind]
    if key not in d:
        d[key] = fmt(len(d) + 1)
    return d[key]

IP4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IP6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.I)
MAC = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I)
SAFE4 = {"0.0.0.0", "127.0.0.1"}

def scrub_str(s):
    s = MAC.sub(lambda x: m("mac", x.group(0).lower(), lambda n: "00:00:5e:00:53:%02x" % (n % 256)), s)
    s = IP6.sub(lambda x: m("ip6", x.group(0).lower(), lambda n: "2001:db8::%x" % n), s)
    s = IP4.sub(lambda x: x.group(0) if x.group(0) in SAFE4 or ".".join(x.group(0).split(".")[:3]) == "192.0.2"
                else m("ip4", x.group(0), lambda n: "192.0.2.%d" % (n % 250 + 1)), s)
    return s

HOSTKEYS = {"name", "hostname", "nodename", "client_name"}
def scrub(o, key=""):
    if isinstance(o, dict):
        return {k: scrub(v, k) for k, v in o.items()}
    if isinstance(o, list):
        return [scrub(v, key) for v in o]
    if isinstance(o, str):
        if key in HOSTKEYS and o:
            return m("host", o, lambda n: "host-%d" % n)
        if key == "domain":
            return m("dom", o, lambda n: "site-%d.example" % n)
        return scrub_str(o)
    return o

sid = req("POST", "/auth", {"password": pw})["session"]["sid"]
try:
    endpoints = {
        "summary": "/stats/summary", "upstreams": "/stats/upstreams", "history": "/history",
        "clients": "/clients", "devices": "/network/devices", "lists": "/lists", "domains": "/domains",
        "info_version": "/info/version", "info_system": "/info/system", "info_sensors": "/info/sensors",
        "info_host": "/info/host", "info_database": "/info/database", "info_ftl": "/info/ftl",
        "info_messages": "/info/messages", "blocking": "/dns/blocking",
    }
    if os.environ.get("RECORD_QUERIES") == "1":
        endpoints["queries"] = "/queries?length=500"
    for name, path in endpoints.items():
        try:
            data = scrub(req("GET", path, sid=sid))
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            print(f"skip {name}: {e}")
            continue
        with open(os.path.join(out_dir, name + ".json"), "w") as f:
            json.dump(data, f, indent=1, sort_keys=True)
            f.write("\n")
        print("recorded", name)
finally:
    try:
        req("DELETE", "/auth", sid=sid)
    except Exception:
        pass
print("done: review testdata/recorded/ before using any of it")
