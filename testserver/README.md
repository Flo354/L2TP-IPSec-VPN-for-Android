# L2TP/IPsec PSK lab server

A **real** L2TP/IPsec server (strongSwan 5.9.8 + xl2tpd 1.3.18 + pppd 2.4.9 on
Debian bookworm) in a Docker container, configured to match exactly what the
target device — an **Orange Livebox Pro** — offers, so that a from-scratch
Kotlin VPN client can be validated end-to-end from JVM tests.

This is **test infrastructure**. The PSK and credentials are hard-coded on
purpose so tests can hard-code them too. Do not deploy this anywhere.

---

## Quick start

```bash
./run.sh        # build image, create network, start server, attach this container
./verify.sh     # prove it is live AND that the full IPsec->L2TP->PPP path works
./stop.sh       # remove the container (network is left in place)
```

`run.sh` is idempotent: it tears down and recreates the container every time.

## Coordinates the tests hard-code

| | |
|---|---|
| Server IP | `172.28.0.10` |
| Docker network | `l2tplab`, `172.28.0.0/16`, gateway `172.28.0.1` |
| Pre-shared key | `TestPreSharedKey2024!` |
| Username | `vpnuser` |
| Password | `VpnPass123` |
| Ports | UDP **500** (IKE), UDP **4500** (IKE + ESP-in-UDP), UDP **1701** (L2TP) |

`run.sh` also attaches *this* container to the `l2tplab` network, so JVM tests
running here can reach `172.28.0.10` directly.

## Exact algorithms configured

**IKEv1 phase 1 — main mode only, PSK**

| attribute | value |
|---|---|
| Encryption Algorithm (1) | 7 = AES-CBC |
| Key Length (14) | 256 |
| Hash Algorithm (2) | 4 = SHA2-256 |
| Group Description (4) | 14 = MODP-2048 |
| Authentication Method (3) | 1 = pre-shared key |

strongSwan proposal string: `ike=aes256-sha256-modp2048!`
(the `!` makes it exclusive — nothing else is accepted).
PRF is `PRF_HMAC_SHA2_256`, implied by the SHA2-256 hash attribute.

**IPsec phase 2 (quick mode) — ESP, transport mode, no PFS**

| attribute | value |
|---|---|
| Transform ID | 12 = ESP_AES |
| Key Length (6) | 256 |
| Authentication Algorithm (5) | 5 = HMAC-SHA2-256 (128-bit ICV) |
| Encapsulation Mode (4) | **4 = UDP-Encapsulated-Transport** (RFC 3947) |
| SA Life Type (11) / Duration (12) | 1 = seconds / 28800 |

strongSwan proposal string: `esp=aes256-sha256!`, `type=transport`.
No Group Description attribute is sent or required → **no PFS**.

**NAT traversal is forced on** (`forceencaps=yes`): charon fakes the NAT-D
hashes so ESP is *always* wrapped in UDP/4500, even when there is no NAT.
The Android client cannot send raw IP-protocol-50 ESP, so it will always claim
to be behind a NAT — this makes the server behave identically either way.
`verify.sh` proves this with a client that has `forceencaps=no`.

**L2TP** — RFC 2661 on UDP/1701, length bit on, userspace (not pppol2tp).

**PPP**

| | |
|---|---|
| LNS address | `10.10.10.1` |
| Client pool | `10.10.10.100` – `10.10.10.199` |
| DNS pushed | `10.10.10.1`, `8.8.8.8` |
| MTU / MRU | 1350 / 1350 (deliberately below the client's 1400 header budget, so the MRU clamp is exercised) |
| Auth offered | CHAP-MD5 first; MS-CHAPv2 and PAP reachable with one LCP Configure-Nak |
| Disabled | EAP, CCP/MPPE, VJ header compression, BSD/Deflate, PFC/ACFC |

Set `PPP_AUTH=chap|mschapv2|pap` before `run.sh` to pin a single method
instead (default is `any`).

---

## Files

| file | what it is |
|---|---|
| `Dockerfile` | Debian bookworm + strongswan/strongswan-starter, xl2tpd, ppp, iproute2, iptables, tcpdump |
| `entrypoint.sh` | creates `/dev/net/tun` + `/dev/ppp`, loads modules, fixes the container sysctls, starts charon then xl2tpd, streams all three logs to stdout |
| `lab.env` | single source of truth for IPs / credentials, sourced by the scripts |
| `run.sh` | build + network + start + self-attach. Idempotent. |
| `stop.sh` | remove the container (keeps the network) |
| `verify.sh` | full proof-of-life, see below |
| `conf/ipsec.conf` | the `conn L2TP-PSK` shown above |
| `conf/ipsec.secrets` | the PSK |
| `conf/strongswan.conf` | container-specific charon settings (see notes below) |
| `conf/xl2tpd.conf` | LNS config |
| `conf/options.xl2tpd` | pppd options, incl. the auth-method block |
| `conf/chap-secrets` | credentials (also copied to `pap-secrets`) |
| `client/` | a **real** strongSwan+xl2tpd+pppd client, baked into the image, used by `verify.sh` |
| `l2tp_probe.py` | plaintext RFC 2661 SCCRQ prober (liveness + AVP requirements) |
| `ike_probe.py` | IKEv1 main-mode SA-payload prober (what the server accepts/rejects) |
| `captures/` | pcaps written by `verify.sh` (`udp port 500 or 4500 or 1701`), plus `cap-l2tp-plaintext.pcap`: a full L2TP+PPP session **without** IPsec, every byte readable |
| `CLIENT_NOTES.md` | **everything the Kotlin client needs to know**, with wire evidence |

## What `verify.sh` proves

1. the container runs on `172.28.0.10`;
2. charon is alive, `conn L2TP-PSK` is loaded with the transport-mode
   `udp/1701 === udp` selector, and `ipsec.conf`/`ipsec.secrets` still contain
   the exact values the tests hard-code;
3. UDP/500, 4500 and 1701 are bound by charon/xl2tpd;
4. from *this* container, a real RFC 2661 SCCRQ gets an SCCRP back;
   9 IKEv1 main-mode SA probes are accepted/rejected exactly as expected;
5. a real strongSwan + xl2tpd + pppd client in a second privileged sibling
   container completes **IKE → ESP → L2TP → PPP**, gets `ppp0` with an address
   from the pool and pings `10.10.10.1` — once for **MS-CHAPv2**, once for
   **CHAP-MD5**, once for **PAP**, and once with `forceencaps=no` on the client
   to prove the *server* is what forces ESP-in-UDP;
6. the server's own logs show IKE_SA + CHILD_SA established, the NAT-T float to
   UDP/4500, the ESP proposal selected, the L2TP tunnel/session, and pppd
   bringing up an interface.

Exit status is non-zero if anything fails. `VERIFY_QUICK=1 ./verify.sh` runs
only the MS-CHAPv2 client for a faster smoke test.

## Container-specific gotchas that are already handled

* `/dev/net/tun` and `/dev/ppp` are created with `mknod` if the runtime did not.
* `net.ipv4.ip_forward=1`, and `rp_filter` / `accept_redirects` /
  `send_redirects` are set to 0 on **every** interface plus `default`. Leaving
  `rp_filter` on is the classic reason L2TP/IPsec silently fails in a container.
* `charon.install_routes = no` and `install_virtual_ip = no` — charon must not
  touch docker's routing.
* charon's DoS protection (`block_threshold`, `init_limit_half_open`) is raised
  to 200. A client under development abandons a lot of handshakes, and the
  defaults make charon start *silently ignoring* main-mode message 1 from that
  source IP. Note `0` does **not** mean unlimited.
* Noisy/irrelevant plugins (`forecast`, `farp`, `dhcp`, `ha`, …) are disabled.

## Logs

```bash
docker logs -f l2tp-server           # charon + xl2tpd + pppd, interleaved and prefixed
docker exec l2tp-server ipsec statusall
docker exec l2tp-server ip xfrm state
docker exec l2tp-server tail -f /var/log/charon.log
```

Raise charon's verbosity at runtime without restarting:

```bash
docker exec l2tp-server ipsec stroke loglevel ike 4
docker exec l2tp-server ipsec stroke loglevel enc 4   # dumps every payload
```

Read a capture back:

```bash
docker run --rm -v "$PWD/captures:/out" --entrypoint tcpdump l2tp-lab-server:latest \
    -r /out/cap-mschapv2.pcap -n -vvv
```
