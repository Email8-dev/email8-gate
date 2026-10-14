# Sentin8 Email8:Gate — Mail Port Passthrough

## 1. Summary

Email8:Gate is the raw-TCP front door for the well-known mail ports
(SMTP submission 587, SMTPS 465, IMAPS 993, …). It terminates the
TLS/TCP listener set, discovers the MTA/Access instances' actual
binds via the Valkey registry, and passthroughs protocol streams to
them — one Gate owns the well-known ports per host while each
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

See the vertical group docs (`email8/README.md`) for the four-service
mail plane overview.

---

**Design attribution:** email8:gate and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
