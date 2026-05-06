Wireshark Labs

This repository contains detailed packet-level analysis and investigation reports for various network scenarios. Each lab focuses on a specific protocol or network event, utilizing industry-standard traffic captures to identify anomalies, security threats, and configuration errors.
 Lab Overview
1. ARP Cache Poisoning Analysis

File: arp_storm.pcap
An investigation into a deliberate ARP spoofing attack.

    Scenario: A Cisco device flooding a subnet with 622 broadcast ARP requests in under 30 seconds.  

    Key Discovery: Identified a single MAC address claiming multiple sender IPs across different subnets—the definitive signature of an ARP poisoning/Man-in-the-Middle (MitM) attempt.  

    Outcome: Documented the "ARP storm" rate (~21 packets/second) and the systematic mapping of the target subnet.  

2. DNS Infrastructure & Misconfiguration

File: dns.cap
A comparative study of two hosts and their DNS resolution behaviors.

    Normal Behavior: Analyzed Host .8 performing standard mail infrastructure reconnaissance (SPF, MX, and A record lookups) via a local DNS server.

    Security Flag: Identified Host .56 leaking internal Windows Active Directory hostnames (.local namespace) to a public DNS server.

    Outcome: Diagnosed a DNS misconfiguration leading to authentication failures and information disclosure.

3. HTTP Transaction & Ad-Traffic Flow

File: http.cap
A deep dive into the lifecycle of a web request.

    Analysis: Captured the TCP three-way handshake, the retrieval of an 18KB XHTML payload, and the subsequent automatic trigger of Google AdSense tracking.

    Technical Details: Traced the DNS resolution chain from a CNAME to Akamai CDN IP addresses.

    Outcome: Verified a clean HTTP session with 0% retransmissions and successful 200 OK status codes.

🛠 Tools & Methodology

    Analysis Tool: Wireshark

    Key Filters Used:

        dns.flags.rcode == 3 (Identify failed lookups)

        tcp.flags.syn == 1 (Isolate connection handshakes)

        arp.opcode == 1 (Filter ARP requests)  

🔗 Resources

The packet captures analyzed in these labs were sourced from the Wireshark Wiki Sample Captures:
 https://wiki.wireshark.org/samplecaptures
