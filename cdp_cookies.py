"""
cdp_cookies.py - Pull cookies from a Chrome/Edge instance with CDP enabled
Usage: python cdp_cookies.py [port] [-o output.txt] [-n NAME] [-d DOMAIN]
  -n NAME    only show cookies whose name contains NAME (case-insensitive, repeatable)
  -d DOMAIN  only show cookies whose domain contains DOMAIN (case-insensitive, repeatable)
Requires: pip install websockets
"""

import asyncio
import json
import sys
import urllib.request

try:
    import websockets
except ImportError:
    print("Missing dependency: pip install websockets")
    sys.exit(1)


def get_targets(port):
    try:
        with urllib.request.urlopen(f"http://localhost:{port}/json", timeout=3) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"[-] Could not reach localhost:{port}/json — {e}")
        print(f"    Is CDPEnable.exe still running? Is Chrome open?")
        sys.exit(1)


async def cdp_call(ws_url, method, params=None):
    async with websockets.connect(ws_url, max_size=50 * 1024 * 1024) as ws:
        await ws.send(json.dumps({"id": 1, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(await ws.recv())
            if msg.get("id") == 1:
                return msg.get("result", {})


async def main(port, outfile, name_filters, domain_filters):
    targets = get_targets(port)
    pages = [t for t in targets if t.get("type") == "page" and "webSocketDebuggerUrl" in t]

    if not pages:
        print(f"[-] No page targets at localhost:{port}")
        print(f"    Available: {[t.get('type') for t in targets]}")
        sys.exit(1)

    page = pages[0]
    print(f"[+] Target: {page.get('title','(no title)')} — {page.get('url','')[:80]}")

    result = await cdp_call(page["webSocketDebuggerUrl"], "Network.getAllCookies")
    cookies = result.get("cookies", [])

    if name_filters:
        cookies = [c for c in cookies
                   if any(f.lower() in c.get("name","").lower() for f in name_filters)]
    if domain_filters:
        cookies = [c for c in cookies
                   if any(f.lower() in c.get("domain","").lower() for f in domain_filters)]

    label = f"{len(cookies)} cookies"
    if name_filters:   label += f" (name ~ {name_filters})"
    if domain_filters: label += f" (domain ~ {domain_filters})"
    print(f"[+] {label}\n")

    lines = []
    header = f"{'Domain':<40} {'Name':<35} {'Path':<20} Value"
    sep    = "-" * 130
    lines += [header, sep]

    for c in sorted(cookies, key=lambda x: (x.get("domain",""), x.get("name",""))):
        line = (f"{c.get('domain',''):<40} {c.get('name',''):<35} "
                f"{c.get('path',''):<20} {c.get('value','')}")
        lines.append(line)

    output = "\n".join(lines)
    print(output)

    if outfile:
        with open(outfile, "w", encoding="utf-8") as f:
            f.write(output + "\n")
        print(f"\n[+] Written to {outfile}")


if __name__ == "__main__":
    port           = 9222
    outfile        = None
    name_filters   = []
    domain_filters = []

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("-o", "--output") and i + 1 < len(args):
            outfile = args[i + 1]; i += 2
        elif args[i] in ("-n", "--name") and i + 1 < len(args):
            name_filters.append(args[i + 1]); i += 2
        elif args[i] in ("-d", "--domain") and i + 1 < len(args):
            domain_filters.append(args[i + 1]); i += 2
        elif args[i].isdigit():
            port = int(args[i]); i += 1
        else:
            i += 1

    asyncio.run(main(port, outfile, name_filters, domain_filters))
