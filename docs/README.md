# Documentation index

Maintenance documentation for the userland L2TP/IPsec client. Start at the
[project README](../README.md) for what the project is and how to build it; everything below is the
depth behind it.

## The documents

| Document | What it covers |
| --- | --- |
| [architecture.md](architecture.md) | Module layout, the layering, the threading model, who owns which state, the platform seams, known limitations |
| [protocol.md](protocol.md) | What is implemented at each layer with RFC references, and the non-obvious decisions: forced UDP encapsulation, transport mode, the zero inner checksum, NAT-T dialects, MTU |
| [rekeying.md](rekeying.md) | SA lifetimes, why the schedule follows the responder, the 75–85 % jittered deadline, make-before-break, peer-initiated Quick Mode, sequence exhaustion, what is deliberately not covered |
| [android.md](android.md) | `VpnService` lifecycle, why `protect()` matters, foreground service type and permissions, the reconnect policy, the connectivity-callback trap and the teardown-ordering trap |
| [configuration.md](configuration.md) | Every field of `VpnConfig` and `VpnProfile`: meaning, default, when to change it, and how the two map onto each other |
| [testing.md](testing.md) | The test strategy, the Docker lab, how to run each suite including the rekey labs, how the live tests self-skip |
| [troubleshooting.md](troubleshooting.md) | Getting useful logs off a device, what each `TunnelErrorKind` means, a table of observed symptoms and their causes |
| [interoperability.md](interoperability.md) | The Livebox Pro's actual settings and how they map onto the client's defaults, plus what the lab taught us about strongSwan, xl2tpd and pppd |

## Suggested reading orders

**"I have to fix a bug in the handshake."**
[architecture.md](architecture.md) → [protocol.md](protocol.md) →
[troubleshooting.md](troubleshooting.md) → `testserver/CLIENT_NOTES.md`.

**"The tunnel comes up and then dies after an hour."**
[rekeying.md](rekeying.md) → [troubleshooting.md](troubleshooting.md).

**"It works on the lab but not on the router."**
[interoperability.md](interoperability.md) → [protocol.md](protocol.md) →
`testserver/CLIENT_NOTES.md`.

**"It connects and instantly disconnects on the phone."**
[android.md](android.md) — that symptom has two well-known causes, both documented there.

**"I need to add a setting."**
[configuration.md](configuration.md) → [android.md](android.md).

## Conventions used here

* Code is referred to by package and class name, never by line number, because the sources move.
* Wire formats and configuration fragments are quoted literally; Kotlin is not.
* Every "why" that would otherwise look arbitrary is spelled out. If a decision looks strange and is
  not explained, that is a documentation bug — please fix it.
* Limitations are stated rather than glossed over. Each document has its own limitations section.

## Beyond these documents

* `testserver/README.md` — how to operate the Docker lab.
* `testserver/CLIENT_NOTES.md` — the byte-level findings that the client was built from: literal
  accepted SA payloads, probe results, AVP requirements, PPP option exchanges. It is the primary
  source; these documents fold in the durable conclusions but do not replace it.
