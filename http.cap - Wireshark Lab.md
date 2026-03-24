
### 1. File Metadata

|**Field**|**Value**|
|---|---|
|**File**|`http.cap`|
|**Total Packets**|43|
|**Total Bytes**|25,091|
|**Date**|May 13, 2004 — 10:17:12 GMT|
|**Client OS**|Windows XP (NT 5.1)|
|**Browser**|Firefox (Gecko engine, Jan 2004)|
|**Primary Server**|`www.ethereal.com` (Apache)|
|**Secondary Server**|`pagead2.googlesyndication.com` (Google AdSense)|
|**Health**|Clean (0 RST, 0 retransmissions)|

---

### 2. Protocol Hierarchy

- **Ethernet/IPv4**: 100% traffic.
    
- **TCP**: 95.3% packets | 836 bytes overhead.
    
- **UDP (DNS)**: 4.6% packets | 193 bytes.
    
- **HTTP**: 9.3% packets | 1,812 bytes (Headers).
    
- **Payload**: 72% of total bytes (18,070 bytes) is a single XML/XHTML file.
    

---

### 3. DNS Analysis (Filter: `dns`)

- **Query**: `pagead2.googlesyndication.com` (Transaction ID: `0x0023`).
    
- **Transport**: UDP Port 53.
    
- **Resolution Chain**:
    
    1. `pagead2.googlesyndication.com` (CNAME) $\rightarrow$ `pagead2.google.com`
        
    2. `pagead2.google.com` (CNAME) $\rightarrow$ `pagead.google.akadns.net` (Akamai CDN)
        
    3. `pagead.google.akadns.net` (A Record) $\rightarrow$ `216.239.59.104`
        
    4. `pagead.google.akadns.net` (A Record) $\rightarrow$ `216.239.59.99`
        

---

### 4. TCP Three-Way Handshake

**Rule**: $Ack\ Number = Seq\ Number\ Received + 1$

|**Packet**|**Flags**|**Seq**|**Ack**|**Details**|
|---|---|---|---|---|
|**1**|SYN|0|0|Client (Port 3372) $\rightarrow$ Server (Port 80). Win=8760.|
|**2**|SYN-ACK|0|1|Server acknowledges Client Seq 0; starts own Seq 0.|
|**3**|ACK|1|1|Client acknowledges Server Seq 0. Connection Open.|

---

### 5. HTTP Transactions (Filter: `http`)

#### Request 1: Intentional

- **GET**: `/download.html`
    
- **Host**: `www.ethereal.com`
    
- **Referer**: `http://www.ethereal.com/development.html`
    
- **Response**: `200 OK`. Delivered 18,070 bytes of XHTML.
    

#### Request 2: Automatic (Ad Tracking)

- **GET**: `/pagead/ads?client=ca-pub...`
    
- **Trigger**: JavaScript block in Request 1's HTML.
    
- **Host**: `pagead2.googlesyndication.com`
    
- **Referer**: `http://www.ethereal.com/download.html`
    

---

### 6. Chronological Event Summary

1. **Handshake**: Client opens TCP connection to Ethereal server (3 packets).
    
2. **Request**: User requests `download.html`.
    
3. **Delivery**: Apache server sends 18KB XHTML payload.
    
4. **Ad Trigger**: Browser parses HTML, executes Google AdSense JS.
    
5. **DNS Lookup**: Browser queries `pagead2.googlesyndication.com` (cached Ethereal IP used previously).
    
6. **CDN Routing**: DNS returns Akamai CNAME chain and two IPs for redundancy.
    
7. **Ad Fetch**: Browser connects to `216.239.59.104` to retrieve 468x60 banner.
    
8. **Closure**: All connections terminate without errors.
    

---

### 7. Key Display Filters

- `tcp.flags.syn == 1 && tcp.flags.ack == 0`: Isolate connection requests.
    
- `http.request.method == "GET"`: View all outbound requests.
    
- `tcp.analysis.retransmission`: Check for packet loss (Result: 0).
    
- `http.response.code == 200`: Confirm successful deliveries.