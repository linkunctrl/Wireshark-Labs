![[Pasted image 20260327013440.png]]

## Summary

A Cisco device performed a deliberate ARP cache poisoning attack, flooding the subnet with 622 broadcast ARP requests in under 29 seconds. A single MAC address claimed multiple different sender IPs across two subnets — the defining signature of ARP spoofing. No legitimate traffic was present. All target devices on the network received poisoned ARP cache entries.

Arp Request Purpose: systematically sending ARP requests to every possible IP on a subnet to map out which hosts are alive — which IPs have a real MAC address behind them.

---

## Attacker Profile

|Field|Value|
|---|---|
|MAC Address|`00:07:0d:af:f4:54` (Cisco OUI)|
|Observed Sender IPs|`24.166.172.1`, `69.76.216.1` (and others)|
|Target|`ff:ff:ff:ff:ff:ff` (broadcast)|
|Target MACs|`00:00:00:00:00:00` (unknown — ARP request)|

---

## Timeline

|Event|Timestamp|
|---|---|
|First packet|`19:01:05.275344`|
|Last packet|`19:01:34.244450`|
|Total duration|~29 seconds|
|Total packets|622|
|Rate|~21 packets/second|

---

## Investigation Steps

### 1. Protocol Hierarchy

- 100% ARP — 622 packets, no other protocols
- **Finding:** No HTTP, DNS, TCP, or UDP — no legitimate data traffic present

### 2. Conversations (Ethernet Tab)

- 1 conversation only: `00:07:0d:af:f4:54` → `ff:ff:ff:ff:ff:ff`
- **Finding:** Single sender, all packets to broadcast

### 3. Endpoints (Ethernet Tab)

- 2 endpoints — all 622 packets TX from Cisco MAC, all 622 RX at broadcast
- **Finding:** Zero reply traffic — no device responded

### 4. Packet-Level Analysis

- Opcode: Request (1) on every packet — no replies (Opcode 2) anywhere
- Target MAC always `00:00:00:00:00:00` — normal for requests
- Target IP changes each packet — systematic sweep through subnet IPs
- Sub-millisecond intervals between packets — machine-speed flood

### 5. Key Anomaly — Multiple Sender IPs, One MAC

- Packet 142: Sender IP `24.166.172.1`
- Packet 615: Sender IP `69.76.216.1`
- Same MAC, different IPs across two subnets
- **This is the attack signature** — a legitimate device has one IP per interface

---

## Attack Type

**ARP Cache Poisoning / ARP Spoofing**

Every device receiving these broadcasts updates its ARP cache with the sender MAC and sender IP. With one MAC broadcasting fake mappings for dozens of IPs at machine speed, all ARP caches on the subnet are continuously overwritten with poisoned entries — disrupting legitimate traffic forwarding.

**Secondary risk:** If the attacker maps a real host's IP to their own MAC, all traffic destined for that host is redirected to the attacker — a **Man-in-the-Middle (MitM)** attack.

---

## Evidence Summary

|Evidence|Significance|
|---|---|
|622 ARP requests in 29 seconds|Far exceeds normal ARP frequency|
|Zero reply packets|Targets unable to respond or don't exist|
|One MAC, multiple sender IPs|Definitive spoofing signature|
|IPs span two subnets|Wider poisoning scope than single-subnet fault|
|No other traffic|Not incidental — ARP storm is the only activity|
|Cisco OUI|Attacker using or spoofing a Cisco device|

---

## Unknowns

- What caused the storm to stop at packet 622 — manual intervention, crash, or self-resolution
- How many unique fake IPs the attacker cycled through
- Whether any MitM interception occurred after cache poisoning
- Extent of damage to affected devices' ARP caches
- How victim devices recovered

---

## Analyst Notes

> _"Know the limits of your evidence. State what you can prove, flag what remains unknown."_

This capture shows the attack in progress but not its before or after. A fuller investigation would require captures from victim hosts, router logs, and any traffic following the storm window.