# Rekeying

Every IPsec and ISAKMP SA carries a lifetime. When it runs out the peer stops accepting the keys, and
a client that has not replaced the SA first simply goes dark. Replacing both before that happens is
what keeps the tunnel up indefinitely instead of dropping and reconnecting once an hour.

All of this runs on the maintenance thread — see
[architecture.md](architecture.md#threading-model) for why it is not on the packet pump.

## Contents

* [Lifetimes](#lifetimes)
* [Why the responder's lifetime and not ours](#why-the-responders-lifetime-and-not-ours)
* [The 75–85 % jittered deadline](#the-7585--jittered-deadline)
* [Make before break](#make-before-break)
* [Answering a peer-initiated Quick Mode](#answering-a-peer-initiated-quick-mode)
* [Telling deletes apart](#telling-deletes-apart)
* [Rekeying the ISAKMP SA](#rekeying-the-isakmp-sa)
* [Messages for the superseded SA are handed back, not dropped](#messages-for-the-superseded-sa-are-handed-back-not-dropped)
* [ESP sequence exhaustion](#esp-sequence-exhaustion)
* [When a rekey fails](#when-a-rekey-fails)
* [What is deliberately not covered](#what-is-deliberately-not-covered)

## Lifetimes

| SA | Proposed by default | Typical peer answer |
| --- | --- | --- |
| ISAKMP (phase 1) | `phase1.lifetimeSeconds`, 3 hours | strongSwan echoes what we proposed; a Livebox may shorten it |
| IPsec (phase 2) | `phase2.lifetimeSeconds`, 1 hour | strongSwan adds its own Life Type/Duration attributes to the answer |

Both are negotiated as a Life Type (seconds) plus a Life Duration attribute. Kilobyte-based lifetimes
are not requested and are ignored if offered — only a seconds-based duration changes the schedule.

Rekeying can be switched off entirely (`rekeyEnabled = false`), which is only useful for diagnosing a
peer that mishandles it. With rekeying off the tunnel will drop when the first SA expires.

## Why the responder's lifetime and not ours

The schedule is computed from the **lifetime the responder settled on**, which the negotiator
extracts from the peer's SA payload and hands back in `Phase1Result` / `Phase2Result`.

strongSwan echoes back whatever the initiator proposed, so on the lab the two are identical and the
distinction is invisible. A router that shortens it is where it matters: proposing three hours and
being granted ten minutes, then scheduling off our own three hours, would leave the client
renegotiating long after the SA had been torn down — and the symptom is a tunnel that dies at a
fixed interval with no error, because from our side nothing went wrong.

If the peer's answer carries no seconds-based lifetime at all, our own proposed value is used as the
fallback.

## The 75–85 % jittered deadline

```
deadline = now + lifetimeSeconds × uniform(0.75, 0.85)
```

with a floor of ten seconds so a pathologically short lifetime cannot produce a busy loop.

Two reasons for those numbers:

* **Peers commonly rekey at around 90 % of the lifetime.** Going earlier keeps us on the initiator
  side of the exchange, which is much the simpler side to be on: we choose the SPI, we drive the
  three messages, and we know exactly when the new SA is usable. The responder path exists and works
  (below), but it is the path with more ways to go wrong.
* **The jitter stops two tunnels that came up together from rekeying in lockstep for ever.** Without
  it, every client that reconnected after the same outage would hit the same router at the same
  instant on every subsequent cycle.

The 10 % span is deliberately narrow: wide jitter would occasionally push a rekey close enough to the
peer's own deadline that both sides start one.

## Make before break

Rekeying means two generations of SA are alive at once for a short while. The rule is:

* **Outbound switches over at once.** That is what the peer expects the moment it has answered.
* **The SA being replaced stays valid for inbound traffic** for `saOverlapMs` (default 30 s), because
  the peer goes on sending on the old SA until it has installed the new one. Retiring it the instant
  the rekey completes drops the packets already in flight.

```
      t0                t1                        t1+saOverlapMs
      │                 │                         │
 SA-A ├─ in ────────────┼─ in (superseded) ───────┤
      ├─ out ───────────┤
                        │
 SA-B                   ├─ in ─────────────────────────────────────►
                        ├─ out ────────────────────────────────────►
                        │
                    rekey completes
```

**Inbound demultiplexing is on the SPI in the ESP header**, not on "whichever SA is current". The
reader looks the SPI up against the current inbound SA and then against the previous one; anything
matching neither is dropped with a debug line. This is the piece that makes make-before-break
actually work — see [protocol.md](protocol.md#inbound-demultiplexing-during-a-rekey).

When the overlap expires, the superseded SA is dropped and an ESP Delete naming *our* old inbound SPI
is sent, so the peer stops sending on it too.

Everything here is published rather than mutated: the maintenance thread swaps volatile references,
and an SA object is never modified once other threads can see it.

## Answering a peer-initiated Quick Mode

A router on its own schedule will start a Quick Mode of its own. Without an answer its rekey goes
nowhere and it eventually deletes the SA under us — so the responder side is implemented in full.

```
<-- HDR*, HASH(1), SA, Ni [, KE], IDci, IDcr
--> HDR*, HASH(2), SA, Nr [, KE], IDci, IDcr
<-- HDR*, HASH(3)
```

Details that matter:

* **`HASH(1)` is verified before anything else**, in constant time. An unauthenticated Quick Mode
  must not be able to install keys.
* **The first transform we can actually run is selected** from the peer's offer. A transform whose
  encapsulation mode is not UDP-encapsulated is skipped while NAT traversal is active, because this
  client cannot carry plain ESP at all. If nothing matches, a `NO_PROPOSAL_CHOSEN` notify is sent
  before failing.
* **The peer's traffic selectors are echoed verbatim.** Narrowing them is what makes a peer reject
  the answer.
* **Whatever PFS group the peer asked for is honoured**, not only our configured one.
* **A repeated message 1 is answered with the cached message 2**, keyed by message id. A lost
  message 2 makes the peer repeat message 1; replaying the same answer keeps both sides on one SA
  pair instead of negotiating a second one. A handful of recent answers are remembered.
* **A missing `HASH(3)` is logged, not fatal.** The SA is usable as soon as message 2 is on the wire,
  and refusing it at that point would drop traffic the peer is already sending on it.

The new SA pair is installed through exactly the same path as a rekey we started, so the overlap and
the delete behave identically.

## Telling deletes apart

RFC 2408 §3.15: a Delete payload names the **sender's own inbound SPIs**, which are the SPIs *we send
on*. Deciding what a delete *means* is the tunnel's job, not the negotiator's, because only the
tunnel knows which SAs are still in use.

| The peer deleted | Meaning | Action |
| --- | --- | --- |
| an SPI belonging to the **superseded** SA | routine housekeeping after a rekey | forget the superseded SA early; nothing else |
| an SPI belonging to the **live** SA | the peer is tearing down the SA we are using | rekey immediately (the deadline is set to zero) |
| an SPI we do not have | already retired, or not ours | log at debug and ignore |
| the **ISAKMP** SA | we can still carry ESP, but we can no longer rekey or tear down cleanly | renegotiate phase 1 at once |

Getting the first row wrong is the classic bug: after every successful rekey the peer deletes the
previous IPsec SA, and treating that as "the tunnel is gone" tears down a perfectly healthy
connection a few seconds after every rekey. The live rekey test pings *after* the superseded SAs have
been deleted precisely to catch this.

## Rekeying the ISAKMP SA

A phase-1 rekey builds a **brand-new negotiator**, because the cookies and the whole key schedule
belong to one SA and cannot be reused. The old context stays reachable for `saOverlapMs` so a Delete
or a DPD acknowledgement already in flight still decrypts, then it is dropped and an ISAKMP Delete is
sent for it.

Inbound ISAKMP messages are routed by cookie pair: current context first, then the previous one.
Anything matching neither is dropped with a warning.

Note that the ESP SAs are **not** children of the ISAKMP SA in any operational sense here — they keep
working across a phase-1 rekey. That is also true of strongSwan, and the live rekey test asserts it.

## Messages for the superseded SA are handed back, not dropped

A phase-1 rekey runs a **second negotiator on the maintenance thread**, and that thread is the only
consumer of the inbound ISAKMP queue. So for the few round trips a Main Mode takes, the *new*
negotiator is the one draining the queue — while the SA it is replacing is still live and the peer is
still talking to it. Everything arriving for that older SA is addressed to cookies the new negotiator
does not have and encrypted under keys it cannot derive: a DPD `R-U-THERE`, a Delete, a Quick Mode
the peer started.

Dropping those is what makes a peer conclude the tunnel is dead. They are parked instead:

```
IkeTransport.deferForeignMessage(raw)   ─►  deferredIkeQueue (16 slots, in the tunnel)
```

Four properties make this work, and each is load-bearing:

* **The negotiator recognises them by initiator cookie.** Both wait loops — the general
  retransmit loop and the one awaiting Quick Mode `HASH(3)` — hand back anything whose initiator
  cookie is not their own, rather than logging and discarding it.
* **It is deliberately not the same queue.** Putting a message back on the queue the negotiator is
  reading would have it read, reject and requeue the same datagram for ever.
* **The deferred queue is drained first**, ahead of anything still on the normal queue. Those
  messages arrived earlier, and a Delete must not be applied out of order with the exchange that
  followed it.
* **It cannot be drained too early.** The drain runs on the same thread as the rekey, so it cannot
  possibly run before the new context has been installed — which is what stops a deferred message
  from being attributed to the SA that was current when it arrived. By the time it runs, the current
  and previous contexts both name the SA they should, and the ordinary cookie-pair routing applies.

The queue is bounded at 16 datagrams and **drops on overflow rather than blocking**: the only thread
that empties it is the very thread a rekey is blocking, so waiting for room would deadlock the tunnel
outright. An overflow logs a warning; a peer would have to be unusually chatty during the handful of
round trips a Main Mode takes to reach it.

## ESP sequence exhaustion

RFC 4303 §3.3.3 forbids reusing a sequence number, so the SA has to be replaced *before* the 32-bit
counter wraps. The outbound SA reports itself exhausted a small margin below `2^32`, leaving room for
the packets already in flight, and the maintenance thread treats that exactly like an expired
lifetime and rekeys immediately. If a packet is ever encoded past the maximum the SA raises rather
than wrapping.

At any plausible rate this fires long after the lifetime does; it exists so that a very fast link
with a very long lifetime cannot silently reuse a sequence number.

## When a rekey fails

* A failure increments a counter and pushes the next attempt back by a fixed retry delay, well inside
  the remaining lifetime so there is room to try again.
* After a small number of consecutive failures the maintenance thread records a failure, which the
  packet pump turns into the tunnel's failure — `IPSEC_SA_FAILED`. The service then reconnects
  according to its backoff policy; see [android.md](android.md#the-reconnect-policy).
* A successful rekey resets the counter.

Failing the tunnel rather than limping on is deliberate: once the SA expires the peer stops accepting
our packets anyway, and a clean reconnect recovers in seconds, whereas a tunnel that stays "connected"
while dropping everything is much harder for a user to diagnose.

## What is deliberately not covered

**A peer that renegotiates phase 1 by starting its own Main Mode.** Such a message arrives under an
initiator cookie we know nothing about; it is dropped with "an ISAKMP message for an SA we do not
know", and the tunnel eventually falls back to reconnecting. Implementing the responder side of Main
Mode would mean a second, structurally different state machine and an identity/PSK check on the
inbound side, for a case that rekeying phase 1 well before the peer's own deadline prevents in
practice.

**Kilobyte-based lifetimes.** Only seconds are proposed and only seconds change the schedule. A peer
that insists on a volume-based lifetime will expire the SA without us noticing; the ESP sequence
check is the only volume-shaped safety net.

**Rekeying across a network handover.** A change of underlying network invalidates the source address
that both NAT-D hashes were computed over, so the tunnel is rebuilt from scratch rather than rekeyed.
See [android.md](android.md#the-connectivity-callback-trap).

**Commit-bit / phase-2 completion handshakes.** The ISAKMP Commit flag is not implemented in either
direction.

**Unbounded deferral during a phase-1 rekey.** Messages for the SA being replaced are handed back and
processed once the rekey finishes (above), but the queue holding them is 16 datagrams deep and drops
the rest. That is a bounded-buffer decision, not a protocol one; blocking instead would deadlock the
thread that is supposed to empty it.

## Verifying it

Two live tests cover the two directions, both against a lab with deliberately short lifetimes. They
watch both counters increase, ping in between, and — the important part — ping again *after* the
superseded SAs have been deleted. Commands and environment variables are in
[testing.md](testing.md#the-rekey-labs).
