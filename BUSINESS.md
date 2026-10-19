# Email8:Gate - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Email8:Gate **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

Email8:Gate is the **front door for the mail Internet**: it delivers:

- **Stable, well-known ports** - mail clients and foreign MX servers
  connect to TCP 25, 465, 587, 143, 993, 110, 995, and 4190. Those
  numbers are load-bearing business expectations baked into every RFC
  client implementation and every MX record on earth; the Gate keeps
  them fixed while everything behind it moves.
- **Zero-downtime mail operations** - mail must keep flowing while the
  platform upgrades services behind the door; the Gate re-dials healthy
  instances by the second, so rolling upgrades are invisible to
  clients.
- **Protocol transparency with a real client address** - backend
  services still see the true client IP/port via PROXY protocol v2, so
  rate limiting, greylisting, and abuse controls work as if clients
  connected directly.
- **One door per host** - a single listener set per node eliminates
  port-collision fights among replicas and keeps firewall rules and
  DNS hygiene trivially correct.

## 2. Business Scope (What the Service Provides)

| # | Capability area | What the business gets |
|---|---|---|
| 1 | Well-known port listeners | 25 (SMTP/MX), 465 (SMTPS), 587 (submission), 143 (IMAP), 993 (IMAPS), 110 (POP3), 995 (POP3S), 4190 (Sieve) bound once per host |
| 2 | Instance discovery | Maps each listener to live healthy MTA/Access instances from the fleet registry (1s cache) |
| 3 | Byte passthrough | Bidirectional, protocol-transparent stream forwarding |
| 4 | Client identity passthrough | PROXY v2 headers so backends rate-limit and greylist on the real client address |
| 5 | Fleet resilience | Upstream eviction on failed connects, retry-to-next-instance, stale-cache tolerance during registry refresh gaps |
| 6 | Connection governance | Per-listener concurrent-connection caps with backpressure (overload sheds excess connections) |
| 7 | Zero-downtime upgrades | SO_REUSEPORT reuse for gate restarts; stop-first upgrade policy for full swaps |
| 8 | Traffic telemetry | Connection/byte/unavailable counters exposed for ops dashboards |
| 9 | Admin console | `gate` admin page (listener table + counters) rendered remotely in the platform dashboard |
| 10 | Health | Service health endpoint for fleet supervision |

**What the service does NOT own (business boundary):**

| Out of scope | Owned by |
|---|---|
| SMTP dialogue, spam checks, queueing, delivery | Email8:Mta |
| IMAP/POP3/Sieve/DAV protocol sessions | Email8:Access |
| Mail data | Email8:Store / Sentin8:Storage |
| TLS certificate issuance/rotation | Sentin8:Acme (implicit-TLS is terminated at the owning service through listener config) |
| Authorization decisions on protocol traffic | Shield inside Mta/Access - the Gate performs no policy evaluation of mail traffic |
| Event transport, scheduling, storage infra | Sentin8:Bus, Sentin8:Cron, Sentin8:Storage (platform) |
| External DNS records (MX/SPF/autodiscover) | The tenant's DNS + platform provisioning flows |

## 3. Business Capabilities

### 3.1 Port ownership

| Capability | Business rule |
|---|---|
| Bind well-known ports | The Gate is the ONLY mail listener on 25/465/587/143/993/110/995/4190 on a fleet node; one authoritative door avoids collisions and misconfiguration |
| Listener disabling | An unset port env removes that listener from the door (e.g. sites that front the Gate with their own edge) |
| Reuse-port restarts | Optional `SO_REUSEPORT` lets a new Gate binary take over connections mid-life for self-upgrades |

### 3.2 Routing the stream

| Capability | Business rule |
|---|---|
| Service mapping | `smtp`/`submission`/`submissions` → Mta; `imap`/`imaps`/`pop3`/`pop3s`/`sieve` → Access (catalog-declared) |
| Instance selection | Round-robin across Active instances with health freshness ≤30s; deterministic ordering keeps distribution stable |
| Live binds | Backend instances publish their actual (ephemeral) bound ports; the Gate dials the published port, falling back to the catalog's raw port |
| Failure handling | Failed dials evict the instance and retry up to 3 attempts across other instances; when all are down, the connection is refused cleanly |
| Stale tolerance | If a registry refresh returns nothing, the previous healthy set is retained briefly rather than dropping traffic |

### 3.3 Client identity & protection

| Capability | Business rule |
|---|---|
| PROXY v2 prepend | The Gate speaks PROXY protocol v2 to backends (default on), carrying real client IP/port; backends consume it before any protocol bytes |
| Byte counters | Connections, bytes in/out, active sessions, upstream-unavailable events are counted per listener for ops visibility |
| Overload shedding | Concurrent-connection semaphore (default 2048) refuses excess with a clean disconnect instead of queue collapse |

### 3.4 Observability and admin

| Capability | Business rule |
|---|---|
| Telemetry snapshot | `GET /v1/gate/telemetry` exposes counters for probing |
| Admin page | The `gate` RFW page lists live listeners (name/port/upstream) and counters, gated on `email8:gate:telemetry:read` |

## 4. Business Events (Outbound)

Email8:Gate publishes **no domain events** - it never parses mail, and
traffic metrics ride the telemetry counters instead. The Shield
hot-reload consumer rides the service's `-policy` workload, and the
audit journal drains to the platform audit API.

| Channel | Content |
|---|---|
| Metrics | `connections_total`, `bytes_in/out_total`, `active_connections`, `upstream_unavailable_total` via the telemetry snapshot / admin page |
| Audit journal → Sentin8:Sys `POST /v1/audit` | Operational audit only (the leaf journal is drained by the shell pusher) |

**Inbound (consumed):** none.

## 5. Business Rules & Invariants

1. **One door per host**: unless reuse-port is explicitly enabled, the
   Gate holds each well-known port exclusively - two Gates on one node
   would mean undefined mail routing.
2. **The Gate never interprets mail bytes**: it cannot alter, drop, or
   slow-track protocol content - all mail behavior belongs to Mta and
   Access; the Gate's influence is limited to connection acceptance and
   dial targets.
3. **Client IP fidelity**: backend services always receive the real
   client address (PROXY v2); abuse controls are never blinded by the
   passthrough.
4. **Unavailable upstreams fail fast**: a connection with no healthy
   backend is refused at the door within seconds - clients get a clean
   failure, not a hang.
5. **Registry truth**: dial targets come only from the fleet registry
   plus published listener maps - never from hardcoded endpoints.
6. **No mail data touch**: the Gate has no database, no blob access, no
   secrets beyond its Valkey identity - a compromised Gate cannot read
   mail.

## 6. Target-User Roles & Use Cases

| Persona | What they do with Email8:Gate |
|---|---|
| Internet senders / other MTA operators | Connect to :25 to hand off mail for hosted domains |
| End users' mail clients | Connect to :993/:143 (IMAP), :587/:465 (submission), :110/:995 (POP3) |
| Sieve users' clients | Connect to :4190 to manage server-side filters |
| Email administrators | Watch the gate dashboard page to confirm listeners and traffic |
| Platform operators | Perform rolling upgrades relying on instance eviction/re-dial and telemetry counters |
| Security operations | Rely on PROXY v2 so per-IP blocking/greylisting upstream is accurate |

## 7. KPIs / Success Criteria

| Category | Target |
|---|---|
| Availability | Mail ports remain accepted through backend rolling upgrades; failed upstreams re-dialed within one attempt triple |
| Latency | Passthrough overhead negligible (bytes forwarded, not parsed); connect-to-backend dial typically same-host/LAN |
| Correctness | 100% of backends receive a valid PROXY v2 header before protocol bytes |
| Overload behavior | Connection cap enforced deterministically; counters reflect refused connections (`upstream_unavailable`) |
| Auditability | Listener health and traffic counters are always available for incident response |

## 8. Dependencies & Reliance on Other Services

| Relied on | For |
|---|---|
| Email8:Mta | Upstream for smtp/submission/submissions listeners |
| Email8:Access | Upstream for imap/imaps/pop3/pop3s/sieve listeners |
| Valkey (fleet registry) | Service-instance status/health and published listener maps (cert-identity ACL) |
| Sentin8:Acme / platform TLS | Certificate material consumed by implicit-TLS backend listeners |
| Shield (Sentin8:Policy) | Admin-page authorization and the telemetry-read policy set |
| Sentin8:Sys | Audit journal drain |
| Sentin8:Cron / Sentin8:Bus | Not used - Gate is stateless and has no queue/event surface |

## 9. Acceptance Criteria

1. Every advertised listener binds its well-known port and forwards to
   at least one healthy instance of the mapped service.
2. Killing all instances of a backend stops new connections on those
   listeners cleanly (refused, counted) and recovers the moment an
   instance goes Active again.
3. A rolling `upgrade-instance` of Mta or Access causes no client
   handshake failures beyond in-flight connection handling - new dials
   target the new instances immediately.
4. Every backend stream begins with a correctly formed PROXY v2 header
   (unit-tested byte layout, mixed-family handled).
5. The gate admin page reflects live listeners and counters; access to
   it requires the telemetry-read scope.
6. Disabling a listener via env truly frees the port after restart.
7. `make build`, `make test`, `make lint` pass; the OpenAPI spec matches
   implemented routes.

## 10. Open Business Questions

- Whether an SMTP-level (PROXY-v2-independent) IP allowlist belongs at
  the Gate edge for hostile-network scenarios, or should remain at Mta
  layer where context is richer.
- TLS termination at the Gate itself (today implicit-TLS is terminated
  in the backend services; a terminate-at-Gate mode would centralize
  certificate management).

---

**Design attribution:** email8:gate and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.