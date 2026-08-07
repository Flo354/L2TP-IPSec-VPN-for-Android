# CLIENT_NOTES.md — what the Kotlin client has to put on the wire

Everything here was **observed against the running lab server**
(strongSwan 5.9.8 / xl2tpd 1.3.18 / pppd 2.4.9, Debian bookworm), not read out
of an RFC. Sources of evidence, in order of strength:

* `tcpdump -i any -n -s0 -w cap.pcap 'udp port 500 or 4500 or 1701'` on the
  client side, read back with `tcpdump -r cap.pcap -n -vvv -X` — the phase-1
  exchange is in the clear, so those bytes are literal.
* charon's own parse/generate trace at `ipsec stroke loglevel enc 4`, which
  hex-dumps every payload *after decryption* — this is where the quick-mode
  numbers come from.
* `ike_probe.py` and `l2tp_probe.py` in this directory: hand-rolled probes that
  send deliberately-varied IKEv1 SA payloads / L2TP SCCRQs and report what the
  server accepts. Re-run them any time: `python3 ike_probe.py 172.28.0.10`.

Anything I could **not** prove is marked *(not verified)*.

---

## 0. The shape of the whole thing

```
UDP/500   IKEv1 main mode msg 1..4       (cleartext SA/KE/Nonce/NAT-D)
          -- both sides detect "NAT" -> float to 4500 --
UDP/4500  [4 zero bytes] IKEv1 main mode msg 5..6   (encrypted ID+HASH)
UDP/4500  [4 zero bytes] IKEv1 quick mode msg 1..3  (encrypted SA/Nonce/ID/NAT-OA)
UDP/4500  ESP(spi,...) { UDP 1701 -> 1701 { L2TP control: SCCRQ/SCCRP/SCCCN } }
                                          { L2TP control: ICRQ/ICRP/ICCN     }
                                          { L2TP data: PPP LCP / CHAP / IPCP }
                                          { L2TP data: PPP IPv4 payload      }
```

There is **no** raw IP-protocol-50 ESP anywhere: the server has
`forceencaps=yes`, so ESP is always UDP-encapsulated on 4500. This was proven
by running a client with `forceencaps=no` — the SA still came out as
`encap type espinudp sport 4500 dport 4500`.

---

## 1. IKEv1 phase 1 — main mode message 1

### 1.1 Literal bytes the server accepts

This is the SA payload a strongSwan client sent and the server accepted,
copied out of the pcap (offsets are into the ISAKMP message):

```
0d 00 00 38                    SA payload : next=13 (Vendor ID), len=0x38 (56)
00 00 00 01                      DOI       = 1  (IPSEC)
00 00 00 01                      Situation = 1  (SIT_IDENTITY_ONLY)
  00 00 00 2c                    Proposal  : next=0 (last), len=0x2c (44)
  01 01 00 01                      #1, protocol=1 (ISAKMP), SPI size=0, 1 transform
    00 00 00 24                    Transform: next=0 (last), len=0x24 (36)
    01 01 00 00                      #1, transform-id=1 (KEY_IKE), reserved
      80 01 00 07                    Encryption Algorithm (1)  = 7  AES-CBC
      80 0e 01 00                    Key Length           (14) = 256
      80 02 00 04                    Hash Algorithm       (2)  = 4  SHA2-256
      80 04 00 0e                    Group Description    (4)  = 14 MODP-2048
      80 03 00 01                    Authentication Method(3)  = 1  pre-shared key
      80 0b 00 01                    Life Type            (11) = 1  seconds
      80 0c 00 00                    Life Duration        (12) = 0
```

All attributes are in **TV form** (high bit of the type field set, 2-byte
value). The server's message-2 SA payload is byte-identical apart from the
payload chaining — strongSwan simply echoes the transform it selected.

Note `Life Duration = 0`: strongSwan does not care. See 1.3.

### 1.2 ISAKMP header for message 1

```
initiator cookie   8 random bytes, non-zero
responder cookie   8 zero bytes
next payload       1   (SA)
version            0x10 (major 1, minor 0)
exchange type      2   (Identity Protection = main mode)   <-- NOT 4 (aggressive)
flags              0
message ID         0
length             28 + payloads
```

`ipsec.conf` has no `aggressive=yes`, and charon refuses aggressive mode with
PSK by default. **Main mode only.**

### 1.3 What the server actually accepts — probe results

`python3 ike_probe.py 172.28.0.10` (9 variants, all reproducible):

| # | variant | result |
|---|---|---|
| 1 | strongSwan's own set (enc, keylen, hash, group, auth, lifetype, lifeduration) | **ACCEPTED** |
| 2 | minimal: enc, keylen, hash, group, auth — **no lifetime attributes at all** | **ACCEPTED** |
| 3 | lifetime as a 4-byte **TLV** (`00 0c 00 04 00 00 70 80`) instead of TV | **ACCEPTED** |
| 4 | attributes in a **different order** (auth, group, hash, keylen, enc) | **ACCEPTED** |
| 5 | 3 transforms where only #3 matches (3DES/SHA1, AES-128, AES-256/SHA-256) | **ACCEPTED** |
| 6 | AES **without** a Key Length attribute | NOTIFY NO_PROPOSAL_CHOSEN (14) |
| 7 | AES-**128** instead of AES-256 | NOTIFY NO_PROPOSAL_CHOSEN (14) |
| 8 | **SHA-1** instead of SHA-256 | NOTIFY NO_PROPOSAL_CHOSEN (14) |
| 9 | **MODP-1024** instead of MODP-2048 | NOTIFY NO_PROPOSAL_CHOSEN (14) |

Take-aways for the client:

* Lifetime attributes are **optional** and may be TV or TLV. Don't sweat them.
* Attribute **order does not matter**.
* The **Key Length attribute is mandatory** for AES — without it charon reads
  the proposal as `AES_CBC` with no key size and rejects it. This is the single
  most common way to get a silent-looking `NO_PROPOSAL_CHOSEN`.
* You may offer several transforms; the server picks the first that matches and
  echoes exactly that one transform back in message 2. Read the transform
  number in the reply to know which one won.
* A rejection is an **unencrypted INFORMATIONAL** with
  `NOTIFY NO_PROPOSAL_CHOSEN (14)`, sent from UDP/500 with the same cookies.

### 1.4 Vendor ID payloads

The strongSwan client sent **five** VIDs, and the server replied with **four**
(exact bytes from the pcap):

| bytes | meaning | client→server | server→client |
|---|---|---|---|
| `09002689dfd6b712` (8 B) | XAUTH | yes | yes |
| `afcad71368a1f1c96b8696fc77570100` | Dead Peer Detection (RFC 3706) | yes | yes |
| `4048b7d56ebce88525e7de7f00d6c2d3` + `80000000` (20 B) | IKE fragmentation (Microsoft) | yes | yes |
| `4a131c81070358455c5728f20e95452f` | **NAT-T RFC 3947** = MD5("RFC 3947") | yes | **yes** |
| `90cb80913ebb696e086381b5ec427b1f` | draft-ietf-ipsec-nat-t-ike-02\n | yes | **no** |

What matters for the client:

* **You must send the RFC 3947 NAT-T vendor ID.** Without a NAT-T VID the
  server will not offer NAT-T, will not float to 4500, and will expect raw
  ESP — which Android cannot send.
* The server offered both back when both were sent, choosing RFC 3947. So
  **send only `4a131c81070358455c5728f20e95452f`** and use the RFC 3947 payload
  numbers (see 1.5). If you send only the draft-02 VID, strongSwan will use the
  *draft* payload numbers 130/131 instead *(not verified — we always sent the
  RFC VID)*.
* XAUTH / DPD / fragmentation VIDs are optional to send. The server sends them
  unconditionally; **ignore VIDs you do not recognise**.
* MODP-2048 keeps message 3 at ~424 bytes, so **IKE fragmentation is never
  needed** even though the server advertises it.

### 1.5 NAT-D (main mode messages 3 and 4)

Payload type **20** (`0x14`) — the RFC 3947 number, *not* the draft's 130.
tcpdump prints it as `(pay20)`.

Each NAT-D payload body is a bare hash, with the size of the negotiated phase-1
hash — here **32 bytes** (SHA-256), confirmed by charon logging
`natd_hash => 32 bytes`.

```
HASH = SHA256( CKY-I || CKY-R || IP-address (4 bytes) || Port (2 bytes, BE) )
```

Ordering, confirmed by charon's `received dst_hash` / `received src_hash` log
lines: the **first** NAT-D payload is the hash of the *peer's* (destination)
address/port, subsequent ones are the sender's own (source) address/port.
Two payloads is what both sides send.

**To claim you are behind a NAT** (which the Android client always must),
put a *random* 32-byte value in your own source NAT-D payload instead of the
real hash. That is exactly what `forceencaps=yes` does — the server logged
`faking NAT situation to enforce UDP encapsulation` when the peer did not, and
`remote host is behind NAT` when the peer did.

### 1.6 Floating to UDP/4500

As soon as either side detects a NAT, both switch source and destination port
to 4500 starting with **main mode message 5**. The server logs:

```
local  endpoint changed from 172.28.0.10[500] to 172.28.0.10[4500]
remote endpoint changed from 172.28.0.3[500]  to 172.28.0.3[4500]
```

On UDP/4500 every **IKE** message is prefixed with a **4-byte non-ESP marker
`00 00 00 00`**; ESP packets are not (their first 4 bytes are the SPI, which is
never 0). tcpdump shows this as `NONESP-encap:` vs `UDP-encap: ESP(...)`.

### 1.7 Identity and HASH (messages 5 and 6)

Message 5 observed: `[ ID HASH N(INITIAL_CONTACT) ]`, encrypted with SKEYID_e.

* Identity payload: type **1 = ID_IPV4_ADDR**, protocol 0, port 0, 4-byte
  address, is what strongSwan sends.
* **The identity does not have to be an IP address.** A client run with
  `leftid=@android-test-client` (type 2, ID_FQDN) was accepted:
  `IKE_SA established between 172.28.0.3[android-test-client]...172.28.0.10[...]`.
  `ipsec.secrets` uses a wildcard (`%any %any : PSK ...`) and `right=%any`, so
  any identity type/value works. Use whatever is convenient.
* The server's own ID is **ID_IPV4_ADDR `172.28.0.10`**.
* `N(INITIAL_CONTACT)` is optional. `uniqueids=no` is set, so the server will
  not tear down other SAs from the same peer either way.

**A wrong PSK does not produce a clean error.** SKEYID differs, so the server
cannot decrypt message 5. It logs `invalid ID_V1 payload length, decryption
failed?` and answers with an **INFORMATIONAL carrying N(PAYLOAD_MALFORMED)
encrypted under the server's keys** — which the client also cannot decrypt. The
client-side symptom is `giving up after 3 retransmits / peer not responding`.
If your handshake dies exactly here, suspect the PSK or your SKEYID/HASH_I
derivation, not the network.

### 1.8 Rate limiting — read this before you debug for an hour

charon's DoS protection counts **half-open IKE SAs per source IP**. With the
stock settings, after a handful of abandoned handshakes it starts *silently
dropping* main mode message 1:

```
ignoring IKE_SA setup from 172.28.0.2, per-IP half-open IKE_SA limit of 4 reached
```

There is no reply at all — it looks exactly like the server being down. The lab
server therefore sets `block_threshold = 200`, `init_limit_half_open = 200`,
`init_limit_job_load = 200`, `half_open_timeout = 10` in `strongswan.conf`.
Note that **`0` is not "unlimited"** — it did not disable the check; a large
number is what works. A real Livebox will have the defaults, so a client that
abandons handshakes will get blackholed there.

Related, and equally confusing: **use a fresh random initiator cookie for every
connection attempt.** charon keys its half-open IKE_SAs on the initiator
cookie, and a repeated cookie is treated as a *retransmission* of message 1.
While the old half-open SA is still alive (up to `half_open_timeout`, 30 s by
default) your "new" attempt gets the cached response — or nothing at all if the
payloads differ. Developing `ike_probe.py` with a deterministic cookie made it
fail intermittently for exactly this reason.

---

## 2. Phase 2 — quick mode

The whole quick mode is encrypted, so these bytes come from charon's `enc 4`
post-decryption dump.

### 2.1 Message 1 (client → server), decrypted body, byte for byte

```
01 00 00 24  <32-byte HASH(1)>        HASH_V1  : next=1 (SA)
0a 00 00 2c 00 00 00 01 00 00 00 01   SA_V1    : next=10 (Nonce), len=44,
                                                 DOI=1 (IPSEC), Situation=1
  00 00 00 20 01 03 04 01 ce 6a 85 4f   Proposal: next=0, len=32, #1,
                                                  protocol=3 (ESP), SPI size=4,
                                                  1 transform, SPI=CE6A854F
    00 00 00 14 01 0c 00 00             Transform: next=0, len=20, #1,
                                                   transform-id=12 (ESP_AES)
      80 06 01 00     Key Length            (6) = 256
      80 05 00 05     Authentication Alg    (5) = 5  HMAC-SHA2-256
      80 04 00 04     Encapsulation Mode    (4) = 4  UDP-Encapsulated-Transport
05 00 00 24  <32-byte nonce>           NONCE_V1 : next=5 (ID)
05 00 00 0c 01 11 00 00 ac 1c 00 03    IDci     : next=5 (ID), len=12
                                                  ID type=1 (ID_IPV4_ADDR)
                                                  protocol=17 (UDP), port=0
                                                  address=172.28.0.3
15 00 00 0c 01 11 06 a5 ac 1c 00 0a    IDcr     : next=21 (NAT-OA), len=12
                                                  ID type=1, protocol=17,
                                                  port=0x06a5 = 1701
                                                  address=172.28.0.10
15 00 00 0c 01 00 00 00 ac 1c 00 03    NAT-OA(i): next=21, type=1,
                                                  proto=0, port=0, 172.28.0.3
00 00 00 0c 01 00 00 00 ac 1c 00 0a    NAT-OA(r): next=0,  type=1,
                                                  proto=0, port=0, 172.28.0.10
```

### 2.2 Message 2 (server → client), decrypted body

Same shape; the SA payload is 8 bytes longer because the server **adds the
lifetime attributes**:

```
0a 00 00 34 00 00 00 01 00 00 00 01
  00 00 00 28 01 03 04 01 ca 4a d1 5c      (server's inbound SPI)
    00 00 00 1c 01 0c 00 00
      80 06 01 00     Key Length         (6)  = 256
      80 05 00 05     Authentication Alg (5)  = 5   HMAC-SHA2-256
      80 04 00 04     Encapsulation Mode (4)  = 4   UDP-Encap-Transport
      80 01 00 01     SA Life Type       (1)  = 1   seconds
      80 02 70 80     SA Life Duration   (2)  = 0x7080 = 28800 s (8 h)
```

The IDci/IDcr and both NAT-OA payloads are **echoed back unchanged**.
Message 3 is just `[ HASH ]` (HASH(3)).

### 2.3 The numbers you must get right

| thing | value | why |
|---|---|---|
| Protocol ID in the proposal | **3** (ESP) | |
| SPI size / SPI | **4** bytes, your inbound SPI | the server's reply carries *its* inbound SPI, which is your outbound SPI |
| Transform ID | **12** = ESP_AES | |
| Key Length (attr 6) | **256** | mandatory, same trap as phase 1 |
| Authentication Algorithm (attr 5) | **5** = HMAC-SHA2-256 | ICV is truncated to **128 bits**, i.e. 16 bytes on the wire (`HMAC_SHA2_256_128`) |
| Encapsulation Mode (attr 4) | **4** = UDP-Encapsulated-Transport | **not** 2 (Transport), **not** the draft values 61443/61444 |
| Group Description (attr 3) | **absent** | sending it would request PFS, which the server is not configured for |
| Lifetime | optional in the request; server answers 28800 s | `rekey=no`, so nothing rekeys during a test |

`Encapsulation Mode = 4` is the RFC 3947 value and follows from having
negotiated the RFC 3947 NAT-T vendor ID. With the draft-02 VID it would be
61444 *(not verified)*.

### 2.4 Traffic selectors (IDci / IDcr) — what `leftprotoport=17/1701` implies

The server config is `left=%any leftprotoport=17/1701` /
`right=%any rightprotoport=17/%any`, so:

* **IDcr** (the responder's selector, i.e. the server) **must be**
  ID type 1 (ID_IPV4_ADDR), protocol **17**, port **1701**, address = server IP.
* **IDci** (yours) must be ID type 1, protocol **17**, address = your IP.
  The **port may be 0 (any) or your real L2TP source port** — the strongSwan
  client sent 0 and it matched. Sending 1701 also matches.

charon logs the narrowing:

```
config: 172.28.0.3/32[udp],       received: 172.28.0.3/32[udp]       => match
config: 172.28.0.10/32[udp/l2f],  received: 172.28.0.10/32[udp/l2f]  => match
```

(`l2f` is just how strongSwan prints UDP port 1701 via `/etc/services`.)

The resulting kernel policy on the server is

```
src 172.28.0.10/32 dst <client>/32 proto udp sport 1701  dir out
src <client>/32 dst 172.28.0.10/32 proto udp dport 1701  dir in
```

so **only UDP traffic to/from port 1701 goes through the SA**. Anything else
you send inside ESP will be dropped.

If you are behind a real NAT, put your **pre-NAT (internal) address** in IDci
and in your NAT-OA payload; the server uses the NAT-OA to reconstruct the
original addresses. In the lab there is no NAT, so IDci and NAT-OA both carry
the same address — the NAT-OA path is therefore only *exercised*, not stressed.

### 2.5 NAT-OA

Payload type **21** (`0x15`), RFC 3947. Body layout is identical to an ID
payload: `ID-type(1) protocol(1) port(2) address(4)`, with protocol and port
**zero**. Two are sent, initiator's first then responder's.

strongSwan sends them and echoes them back. RFC 3947 §5.2 requires them for
UDP-encapsulated **transport** mode (the receiver needs the original addresses
to fix TCP/UDP checksums). *We did not test omitting them* — send them.

---

## 3. The ESP data path

* Every packet: `UDP src 4500 dst 4500` → `ESP` (SPI first, so no non-ESP
  marker) → `UDP src/dst 1701` → L2TP.
* **Transport mode**: ESP protects the UDP/1701 datagram only; the outer IP
  header is the original one, there is no inner IP header.
* Cipher `AES-CBC-256` (16-byte explicit IV per packet), integrity
  `HMAC-SHA-256-128` → **16-byte ICV**, computed over the ESP header + IV +
  ciphertext.
* Kernel view on both ends, for reference:

```
src 172.28.0.3 dst 172.28.0.10
    proto esp spi 0xc6f27ebb reqid 1 mode transport
    auth-trunc hmac(sha256) 0x... 128
    enc cbc(aes) 0x...
    encap type espinudp sport 4500 dport 4500 addr 0.0.0.0
```

* **Dead Peer Detection is on**: `dpddelay=30 dpdaction=clear`. After 30 s of
  silence the server sends an ISAKMP INFORMATIONAL `R-U-THERE` (notify 36136)
  and expects `R-U-THERE-ACK` (36137); `dpdtimeout=150`. In practice the L2TP
  HELLO and the PPP LCP echoes keep the link busy so DPD rarely fires, but an
  idle client must answer it. *(DPD was never observed firing in our runs — the
  sessions were too short.)*
* NAT keepalives: charon's `keep_alive` default is 20 s — a 1-byte `0xFF`
  datagram on UDP/4500 to peers it believes are NATed. Ignore inbound ones;
  sending your own is good practice. *(Not observed in our short runs.)*

---

## 4. L2TP (RFC 2661) — what xl2tpd insists on

### 4.0 Develop this layer without IPsec first

The lab server's `conn L2TP-PSK` uses `auto=add`, so strongSwan installs **no
trap policy** and **plaintext L2TP on UDP/1701 is not blocked**. You can bring
up the entire L2TP + PPP stack against `172.28.0.10:1701` with no IPsec at all,
watch every byte with tcpdump, and only then wrap it in ESP. That is how the
byte-level traces below were produced:

```bash
# from any container on the l2tplab network, no IPsec involved
tcpdump -i any -n -s0 -w /out/cap.pcap 'udp port 1701' &
xl2tpd -D -c client.conf -C /var/run/xl2tpd/l2tp-control &
echo "c lab" > /var/run/xl2tpd/l2tp-control
```

(`captures/cap-l2tp-plaintext.pcap` in this directory is exactly that trace.)

Note the opposite is *not* true for the encrypted path: once ESP is in play you
**cannot** see the decapsulated UDP/1701 traffic with tcpdump on either
endpoint — the kernel re-injects the inner packet past the point where tcpdump
taps. Debug L2TP in the clear, then turn IPsec on.

### 4.1 Headers — literal bytes

**Control message**: `T=1 L=1 S=1 Ver=2` → first 2 bytes **`C8 02`**, then
`Length(2) TunnelID(2) SessionID(2) Ns(2) Nr(2)`, then AVPs.

```
c802 006d 0000 0000 0000 0000   SCCRQ  : len=0x6d, tid=0, sid=0, Ns=0, Nr=0
c802 000c 7464 0000 0001 0002   ZLB ACK: len=12, tid=0x7464, sid=0, Ns=1, Nr=2
```

A **ZLB** is just that 12-byte header with no AVPs — it is both the normal ACK
and what you get back when the server decides to ignore a malformed request.

**Data message**: `T=0 L=1 S=0 Ver=2` → first 2 bytes **`40 02`**, then
`Length(2) TunnelID(2) SessionID(2)` and straight into the PPP frame. No Ns/Nr
(`flow bit = no`), no offset field.

```
4002 0025 7464 f20d ff03 c021 0101 0019 ...
^^^^      ^^^^ ^^^^ ^^^^ ^^^^
|         tid  sid  HDLC PPP protocol (LCP)
flags                addr+ctrl
```

**Addressing rule**: always put the IDs *the peer assigned* in the header.
Packets you send carry `TunnelID = <Assigned Tunnel ID from the SCCRP>` and
`SessionID = <Assigned Session ID from the ICRP>`; packets from the server
carry the IDs you assigned in your SCCRQ / ICRQ.

### 4.2 AVP requirements — measured, not guessed

`python3 l2tp_probe.py 172.28.0.10 1701 4 --variants`:

| SCCRQ contents | server reply |
|---|---|
| full (MsgType, ProtoVer, Framing, Bearer, HostName, Vendor, TunnelID, RWS) | **SCCRP** |
| RFC 2661 mandatory only (MsgType, ProtoVer, HostName, Framing, TunnelID) | **SCCRP** |
| no Host Name AVP | **SCCRP** (tolerated) |
| no Protocol Version AVP | **SCCRP** (tolerated) |
| **no Framing Capabilities AVP** | ZLB ACK only — request ignored |
| **no Assigned Tunnel ID AVP** | ZLB ACK only — request ignored |
| **Message Type AVP not first** | ZLB ACK only — request ignored |

The server log for the last case is explicit:

```
handle_avps: First AVP was not message type.
handle_control: bad AVP handling!
Connection -1 closed (First AVP must be message type)
```

So the hard requirements are: **Message Type must be the first AVP**, and
**Framing Capabilities** and **Assigned Tunnel ID** must be present. Send the
full set anyway — it costs nothing.

AVP encoding: `flags+length(2) | vendor(2) | attribute-type(2) | value`, where
the top bit of the first 16-bit word is the **M (mandatory)** bit and the low
10 bits are the total AVP length. Vendor 0 = IETF. The server sets M=1 on
everything except Firmware Revision and Vendor Name.

### 4.3 What the server's SCCRP contains

```
Message Type          M=1  SCCRP (2)
Protocol Version      M=1  0x0100  (version 1, revision 0)
Framing Capabilities  M=1  0x00000003   (async + sync)
Bearer Capabilities   M=1  0x00000000
Firmware Revision     M=0  1680 (0x0690)
Host Name             M=1  "L2TPServer"        <- from `name =` in xl2tpd.conf
Vendor Name           M=0  "xelerance.com"
Assigned Tunnel ID    M=1  <random>
Receive Window Size   M=1  4
```

Use the **Assigned Tunnel ID from the SCCRP** as the Tunnel ID in every
subsequent packet you send; the server uses *yours* when talking to you.
Receive Window Size 4 → the server does flow control; do not have more than 4
unacknowledged control messages in flight.

### 4.4 Message sequence, from the server's log

```
-> SCCRQ  (MsgType=1, ProtoVer, Framing, Bearer, Firmware, HostName, Vendor,
           AssignedTunnelID, RWS)
<- SCCRP  (as above)
-> SCCCN  (MsgType=3)                       # no other AVPs needed
   "Connection established to <ip>, 1701. Local: <srv tid>, Remote: <your tid>"
-> ICRQ   (MsgType=10, AssignedSessionID, CallSerialNumber, BearerType)
<- ICRP   (AssignedSessionID)
-> ICCN   (MsgType=12, TxConnectSpeed, FramingType[, RxConnectSpeed])
   -> the server spawns pppd; PPP starts on the data channel immediately
...
-> StopCCN (MsgType=4, AssignedTunnelID, ResultCode=1) to tear down
```

Observed quirks:

* xl2tpd warns `Peer did not specify transmit speed` if **Tx Connect Speed
  (AVP 24)** is missing from ICCN, but continues. Send it (value 0 is fine).
* **Call Serial Number (AVP 15)** in ICRQ and **Framing Type (AVP 19)** in ICCN
  are read and logged; include them.
* Re-using an Assigned Tunnel ID you already used gets you
  `Peer requested tunnel N twice, ignoring second one` — use a fresh random
  tunnel/session ID per attempt while debugging.
* Every control message must be ACKed; the server ACKs with a **ZLB**
  (control message, zero-length body, correct Ns/Nr). A ZLB with no AVPs is
  also what you get back when the server decides to ignore your message, so
  "got a ZLB but no answer" means *malformed request*, not "still thinking".
* xl2tpd sends **HELLO (MsgType=6)** as a keepalive on an idle tunnel; answer
  with a ZLB ACK. *(Not observed — our sessions were never idle long enough.)*

AVP hex from the real trace, for reference:

```
8008 0000 0000 000a    M=1 len=8  vendor=0 type=0  Message Type = 10 (ICRQ)
8008 0000 000e f20d    M=1 len=8  vendor=0 type=14 Assigned Session ID = 0xF20D
800a 0000 000f 00000001  M=1 len=10 type=15 Call Serial Number = 1
800a 0000 0012 00000000  M=1 len=10 type=18 Bearer Type = 0
0013 0000 0008 "xelerance.com"   M=0 len=0x13 type=8 Vendor Name
```

---

## 5. PPP

Once ICCN is done the server runs:

```
/usr/sbin/pppd /dev/pts/0 passive nodetach 10.10.10.1:10.10.10.100
               auth name L2TPServer debug file /etc/ppp/options.xl2tpd
```

PPP frames ride in L2TP **data** messages. Verified on the wire:

* the payload starts with the HDLC **address/control bytes `FF 03`**
  (`noaccomp` is set, so ACFC is never negotiated and they are always there);
* then the **full 2-byte PPP protocol field**: `C0 21` LCP, `C2 23` CHAP,
  `C0 23` PAP, `80 21` IPCP, `00 21` IPv4 (`nopcomp`, so never compressed to
  one byte);
* **no FCS**, **no 0x7E flags, no byte stuffing** — L2TP already delimits the
  frame. Do not implement async-HDLC escaping.

```
ff03 c021 0101 0019 0104 0578 0206 0000 0000 0305 c223 05 0506 4146 2fcd
^^^^ ^^^^ ^^ ^^ ^^^^ |         |              |             |
|    LCP  |  id len  MRU=1400  ACCM=0         auth: CHAP    magic number
|         Conf-Req                            0xC223, alg 0x05 (MD5)
HDLC addr+ctrl
```

### 5.1 LCP — exact exchange observed

```
server -> [LCP ConfReq id=0x1 <mru 1400> <asyncmap 0x0> <auth chap MD5> <magic 0xa71deeb2>]
client -> [LCP ConfReq id=0x1 <mru 1400> <asyncmap 0x0> <magic 0x59813b1e>]
server -> [LCP ConfAck id=0x1 <mru 1400> <asyncmap 0x0> <magic 0x59813b1e>]
client -> [LCP ConfNak id=0x1 <auth chap MS-v2>]                <- steering the auth method
server -> [LCP ConfReq id=0x2 <mru 1400> <asyncmap 0x0> <auth chap MS-v2> <magic ...>]
client -> [LCP ConfAck id=0x2 ...]
```

* The server offers **CHAP with algorithm 0x05 (CHAP-MD5) first**. This is
  pppd's `CHAP_DIGEST()` preference order, not a policy choice.
* To use **MS-CHAPv2**, answer the server's ConfReq with an
  **LCP Configure-Nak** containing `<auth chap 0x81>`; the server re-requests
  with MS-CHAPv2 and you Ack it.
* To use **PAP**, Configure-Nak with `<auth pap>` (option type 3, length 4,
  protocol 0xC023).
* To use **CHAP-MD5**, just Configure-Ack the first request.
* All three were exercised end-to-end by `verify.sh` and each one was asserted
  in the pppd log before the run was allowed to pass.
* **EAP is never offered.** (`auth` on its own would have made pppd offer EAP
  first; the server config uses explicit `require-chap` / `require-mschap-v2` /
  `require-pap` to remove it. `refuse-eap` alone does *not* do that — it only
  governs the reverse direction. Worth knowing if you ever point the client at
  a stock pppd LNS, which *will* offer EAP.)
* Options the server sends: **MRU** (see the note below), **Async-Control-Character-Map 0**,
  **Magic-Number**, and the auth option. Nothing else. It does **not** send
  PFC/ACFC, and it will reject CCP and VJ (`noccp novj novjccomp nobsdcomp
  nodeflate`), so there is no compression state to implement.
* The server sends an **LCP Echo-Request every 30 s** and drops the link after
  **5** unanswered ones (`lcp-echo-interval 30`, `lcp-echo-failure 5`). You must
  answer Echo-Request with Echo-Reply echoing the 4-byte magic number.
* `lcp-max-configure 30` / `ipcp-max-configure 30`: the server is patient
  (30 retries instead of pppd's default 10) — good while your state machine is
  still slow.

### 5.2 Authentication

**CHAP-MD5** (algorithm `0x05`)
```
ff03 c223 01 f9 0026 17 ddfecb01acc9d44cd511aafc4a538d28d4f1b05abacb77 "L2TPServer"
          ^^ ^^ ^^^^ ^^ ^-- 0x17 = 23 bytes of challenge --^          ^-- name
          |  id len  value-size
          Challenge

ff03 c223 02 f9 001c 10 4704f612f7f086ea341eb6fbe8ee69d7 "vpnuser"
          Response       ^-- 16-byte MD5 --^

ff03 c223 03 f9 0012 "Access granted"      Success
```
The challenge length is **random between 16 and 24 bytes** — do not assume 16.
Response = `MD5(id || password || challenge)`.

**MS-CHAPv2** (algorithm `0x81`)
```
server -> [CHAP Challenge id=0xbd <16 bytes>, name = "L2TPServer"]
client -> [CHAP Response  id=0xbd <49 bytes>, name = "vpnuser"]
server -> [CHAP Success   id=0xbd "S=D4249B05A716E4838F82975B4841C98F69726C40 M=Access granted"]
```
The 49-byte response is `PeerChallenge(16) || Reserved(8, zero) ||
NT-Response(24) || Flags(1)` exactly as in RFC 2759. The Success message
carries `S=<40 uppercase hex>` — the Authenticator Response you should verify.
MPPE is not negotiated (`noccp`), so you never need the master keys.

**PAP**
```
client -> [PAP AuthReq id=0x1 user="vpnuser" password=<hidden>]
server -> [PAP AuthAck id=0x1 "Login ok"]
```
Note PAP is client-initiated: after LCP is up you send Authenticate-Request
without waiting for anything.

Credentials live in `/etc/ppp/chap-secrets` (and an identical `pap-secrets`):
`vpnuser * VpnPass123 *`. The server's own name is **`L2TPServer`**.

### 5.3 IPCP

```
server -> [IPCP ConfReq id=0x1 <addr 10.10.10.1>]
client -> [IPCP ConfReq id=0x1 <addr 0.0.0.0> <ms-dns1 0.0.0.0> <ms-dns2 0.0.0.0>]
server -> [IPCP ConfNak id=0x1 <addr 10.10.10.100> <ms-dns1 10.10.10.1> <ms-dns2 8.8.8.8>]
client -> [IPCP ConfAck id=0x1 <addr 10.10.10.1>]
client -> [IPCP ConfReq id=0x2 <addr 10.10.10.100> <ms-dns1 10.10.10.1> <ms-dns2 8.8.8.8>]
server -> [IPCP ConfAck id=0x2 ...]
```

* Ask for `0.0.0.0` and the server Naks you with an address from the pool
  (`10.10.10.100`–`10.10.10.199`, handed out lowest-free-first).
* DNS is pushed via the Microsoft options **Primary-DNS = 129 (0x81)** and
  **Secondary-DNS = 131 (0x83)**: request them with `0.0.0.0` and take the
  values out of the Nak. Values here: `10.10.10.1` and `8.8.8.8`.
* The server's address is **`10.10.10.1`**; it is a point-to-point peer, not a
  gateway on a subnet.
* **No VJ compression option** is ever sent (`novj novjccomp`), so IPCP option
  2 will not appear.
* **IPv6CP is disabled** on the lab server (`noipv6` in `options.xl2tpd`), so
  you will not get an `0x8057` ConfReq. If you *do* want to exercise that
  (a real Livebox does send IPV6CP), delete that line and the server will send
  one — a v4-only client must answer with an **LCP Protocol-Reject**, exactly
  as pppd itself does:
  `sent [LCP ProtRej id=0x3 80 57 01 01 00 0e 01 0a ...]`.

After IPCP the link carries plain IPv4 with protocol `0x0021`. Pinging
`10.10.10.1` over `ppp0` is the end-to-end check `verify.sh` performs.

> **MRU note.** The captures quoted in this section were taken when the lab ran
> at MRU 1400 and are left as recorded. The lab now ships **1350**, on purpose:
> a real Livebox Pro advertises 1350 while the client's own header budget comes
> out at 1400, so the lower value is what exercises the client's clamp of the
> TUN MTU to the peer's MRU. `options.xl2tpd` is the authority; `LiveServerE2eTest`
> asserts the resulting TUN MTU.

---

## 6. Quick reference — everything the client hard-codes

```
server            172.28.0.10
psk               TestPreSharedKey2024!
user / password   vpnuser / VpnPass123
IKE               main mode, AES-CBC-256 / SHA2-256 / MODP-2048 / PSK
                  attrs: 1=7, 14=256, 2=4, 4=14, 3=1   (all TV)
ESP               transform 12, attrs: 6=256, 5=5, 4=4 (UDP-Encap-Transport)
                  transport mode, no PFS
NAT-T VID         4a131c81070358455c5728f20e95452f
NAT-D / NAT-OA    payload types 20 / 21
IDci              ID_IPV4_ADDR, proto 17, port 0
IDcr              ID_IPV4_ADDR, proto 17, port 1701, 172.28.0.10
L2TP              UDP 1701, flags 0xC802 (control) / 0x4002 (data)
                  address the peer with the IDs it assigned (SCCRP / ICRP)
PPP framing       FF 03 + 2-byte protocol, no FCS, no byte stuffing
PPP auth          CHAP-MD5 offered; Nak to <auth chap 0x81> or <auth pap>
PPP address       peer 10.10.10.1, you get 10.10.10.100..199
DNS               10.10.10.1, 8.8.8.8   (IPCP options 129 / 131)
MTU/MRU           1350                  (see the MRU note in section 5)
```

Development order that works: **plaintext L2TP+PPP on 1701 first** (see 4.0,
fully visible to tcpdump), then IKE phase 1 (also in the clear on 500), then
quick mode, then ESP. Each layer can be validated against this server on its
own.

## 7. Things that are NOT verified

* Behaviour when only the **draft-02** NAT-T vendor ID is offered (payload
  types 130/131, encapsulation mode 61444). We always sent the RFC 3947 VID.
* Behaviour when the **NAT-OA payloads are omitted** from quick mode.
* **DPD `R-U-THERE`** actually firing — the test sessions were never idle for
  30 s. The configuration is there (`dpddelay=30 dpdaction=clear`).
* **IKE fragmentation** — never needed at MODP-2048 message sizes.
* **Rekeying** — `rekey=no` on both phases, so nothing rekeys in a test run.
* Any behaviour behind a **real** NAT: the lab has client and server on the
  same docker bridge, so NAT-T is exercised (forced) but the address
  translation itself is not.
