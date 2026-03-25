
**File:** `dns.cap` (Wireshark official sample) **Focus:** DNS-only capture, 38 packets, 3706 bytes

---

## Step 1 — Protocol Hierarchy

`Statistics → Protocol Hierarchy`

|Layer|Protocol|Packets|% Bytes|
|---|---|---|---|
|Data Link|Ethernet|38|14.4%|
|Network|IPv4|38|20.5%|
|Transport|UDP|38|8.2%|
|Application|DNS|38|56.9%|

**Findings:**

- Pure DNS capture — no TCP, no HTTP
- Every packet terminates at DNS (38 End Packets)
- DNS payload is the largest layer at 56.9% — unusual; application data dominating framing overhead
- UDP used throughout — no handshake, lightweight by design

---

## Step 2 — Conversations

`Statistics → Conversations → UDP tab`

**8 conversations, all on port 53**

|Client|DNS Server|Type|Conversations|
|---|---|---|---|
|192.168.170.8|192.168.170.20|Local (private LAN)|3|
|192.168.170.56|217.13.4.24|Remote (public)|5|

**Key insight:**

- `.8` uses the local DNS server — normal LAN behaviour
- `.56` bypasses local DNS and queries a public server directly — anomalous

---

## Step 3 — DNS Filter

`Filter: dns`

- Total: 38 packets (entire capture is DNS)
- `.8 ↔ .20` — 28 packets (14 queries + 14 responses)
- `.56 ↔ 217.13.4.24` — 10 packets (5 queries + 5 responses)

**Packet pattern:** odd packets = queries, even packets = responses (strict alternating)

---

## Step 4 — Host .8 Analysis

`Filter: ip.src == 192.168.170.8`

**14 queries to local DNS server `.20`, all answered successfully**

|Record Type|Domain|Purpose|
|---|---|---|
|TXT|google.com|SPF record → `v=spf1 ptr ?all`|
|MX|google.com|Mail servers → smtp1–smtp6.google.com|
|A|smtp1–6.google.com|IP addresses (glue records, returned unprompted)|
|NS|isc.org|Nameserver lookup for ISC (BIND maintainers)|

**Conclusions:**

- Traffic pattern matches a **mail client or server** doing full email infrastructure reconnaissance
- Queried SPF → MX → A records in sequence — standard mail setup behaviour
- **Glue records:** packet 4 response included A records for all 6 SMTP servers without being asked — DNS server resolving names it just returned to save extra roundtrips
- **Transaction ID matching confirmed** — e.g. query `0xf76f` matched response exactly
- Recursion Desired set on all queries — client delegating all lookups to the server

---

## Step 5 — Host .56 Analysis

`Filter: ip.src == 192.168.170.56`

**5 queries to public DNS server `217.13.4.24`, all failed**

|Query Domain|Record|Response|
|---|---|---|
|`_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.utelsystems.local`|SRV|NXDOMAIN|
|`GRIMM.utelsystems.local`|A|NXDOMAIN|
|Other `*.utelsystems.local` hostnames|various|NXDOMAIN|

**Conclusions:**

- `.56` is a **Windows machine** doing Active Directory lookups
- `_ldap._tcp` + `_msdcs` + `.local` = Windows AD SRV record pattern
- `Default-First-Site-Name` = uncustomised default AD site name
- Public DNS has no knowledge of `utelsystems.local` → every query returns RCODE 3 (NXDOMAIN)
- **All queries failed** → misconfiguration, not deliberate bypass (a bypass would produce some successful resolutions for public domains)

---

## ⚠️ Security Flag

> **`192.168.170.56` is leaking internal Windows Active Directory hostnames to a public DNS server**

|Indicator|Detail|
|---|---|
|Affected host|192.168.170.56|
|External server|217.13.4.24|
|Leaked namespace|`utelsystems.local`|
|Query types|SRV, A (AD-specific)|
|All responses|NXDOMAIN|
|Likely cause|DNS misconfiguration — should point to 192.168.170.20|
|Impact|AD authentication failure, internal hostnames exposed externally|

**Recommended actions:**

- Set `.56` DNS to `192.168.170.20`
- Investigate how `217.13.4.24` got configured
- Audit whether any other hosts on the LAN are bypassing local DNS

---

## Case Summary

Two hosts are active in this capture. `.8` behaves normally — it uses the local DNS server to resolve 14 queries, predominantly mail-related records for google.com (TXT, MX, A), consistent with a mail client initialising. `.56` is misconfigured — it sends Windows Active Directory SRV and A record queries for `utelsystems.local` to a public DNS server that cannot answer them. Every single query from `.56` returns NXDOMAIN. The all-failure pattern rules out deliberate bypass and points to a broken DNS configuration. As a result, `.56` cannot locate a domain controller and AD authentication on that machine will fail. Internal hostnames are also being leaked to a public server.

---

## Filters Used

|Purpose|Filter|
|---|---|
|All DNS traffic|`dns`|
|Queries from .8|`ip.src == 192.168.170.8`|
|Queries from .56|`ip.src == 192.168.170.56`|
|Traffic to public DNS|`ip.dst == 217.13.4.24`|
|Failed DNS responses|`dns.flags.rcode == 3`|