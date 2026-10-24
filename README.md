# Sentin8 Email8:Gate - Mail Port Passthrough

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/docs/read-3aa757.svg)](https://email8.dev/docs/products/gate)
[![Website](https://img.shields.io/badge/website-email8.dev-1a73e8.svg)](https://email8.dev)

## 1. Summary

Email8:Gate is the raw-TCP front door for the well-known mail ports
(SMTP submission 587, SMTPS 465, IMAPS 993, …). It terminates the
TLS/TCP listener set, discovers the MTA/Access instances' actual
binds via the Valkey registry, and passthroughs protocol streams to
them - one Gate owns the well-known ports per host while each
instance binds OS-ephemeral.

## 2. Architecture

```mermaid
graph TD
    CLIENT[Mail clients] --> GATE[Email8:Gate<br/>well-known ports]
    GATE -- instance discovery --> V[(Valkey registry)]
    GATE -- passthrough --> MTA[Email8:Mta instances]
    GATE -- passthrough --> ACCESS[Email8:Access instances]
```

## 3. Key Traits

- Well-known port ownership: the ONLY mail listener on 25/465/587/
  993/995/143 on a fleet node.
- Instance discovery from Valkey; connections forward to live
  instance binds.
- Protocol-transparent: no mail parsing at the Gate layer.
- Audit journal (AUDJOUR-1, architecture-principles §6.8): the
  `gate.audit_journal` leaf-schema table (migration v2 - the 15-column
  `sentin8_audit::audit_journal_sql` contract, the gate leaf schema's
  first object) is drained to Sys `POST /v1/audit` by the shell's
  boot-8c pusher, presenting the `gate-audit` workload certificate
  (`sentin8:sys:audit:write`).

See the vertical group docs (`email8/README.md`) for the four-service
mail plane overview.

---

**Architecture & Design:** email8:gate and its underlying concepts were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
