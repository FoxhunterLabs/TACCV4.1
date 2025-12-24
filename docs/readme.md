# TACCV4.1 — Reference Secure Pairing Protocol

TACCV4.1 is a **reference implementation** of a PAKE-secured device pairing protocol operating over a fully untrusted relay.

It combines:

* SPAKE2 (password-authenticated key exchange)
* X25519 (ephemeral ECDH)
* ChaCha20-Poly1305 (AEAD secure channel)
* Explicit transcript binding and key confirmation

This project prioritizes **clarity, determinism, and inspectability** over performance or production hardening.

> ⚠️ **WARNING**: This is **not production-ready cryptography**. It is designed for study, evaluation, and controlled experimentation.

---

## What TACCV Is

* A clean, auditable pairing protocol
* Resistant to relay-based MITM attacks
* Explicitly state-gated with strict phase transitions
* Human-verifiable (via SAS) without UI coupling
* Designed to survive hostile network infrastructure

Think: *"secure pairing you can reason about line by line."*

---

## What TACCV Is Not

* A drop-in library for consumer products
* A formally verified system
* Side-channel hardened
* Optimized for throughput or scale
* Designed to hide complexity

If you want "easy," this is not it.
If you want **correct and legible**, keep reading.

---

## High-Level Protocol Flow

1. **Session Creation**
   Relay generates a short human-readable session code and a random session ID.

2. **Profile Negotiation**
   Peers agree on the highest mutually supported cryptographic profile.

3. **PAKE (SPAKE2)**
   Password-derived shared secret without password exposure.

4. **PAKE Confirmation**
   Mutual proof of shared secret + optional SAS display.

5. **Handshake (X25519)**
   Ephemeral key exchange bound to transcript state.

6. **Key Confirmation**
   Explicit confirmation of derived session keys.

7. **Secure Channel**
   ChaCha20-Poly1305 with directional keys and sequence-bound nonces.

Each phase is strictly ordered and enforced.

---

## Repository Structure

```
taccv4.1/
├─ src/taccv/
│  ├─ crypto/        # Cryptographic primitives & constructions
│  ├─ protocol/      # Constants, phases, profiles, transcript
│  ├─ relay/         # Untrusted WebSocket relay server
│  ├─ client/        # Pairing client state machine
│  ├─ util/          # Logging and dependency checks
│  └─ taccv41.py     # CLI entrypoint
│
├─ docs/             # Threat model & design documentation
├─ scripts/          # Local smoke tests
└─ README.md
```

---

## Running Locally

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the relay

```bash
python -m taccv.taccv41 relay
```

### 3. Create a session

```bash
curl -X POST http://localhost:8000/session
```

### 4. Run clients

```bash
python -m taccv.taccv41 client --session CODE --role alice --pin 123456
python -m taccv.taccv41 client --session CODE --role bob   --pin 123456
```

---

## Security Notes

* Relay is assumed **fully hostile**
* All key material is transcript-bound
* Downgrade attacks are explicitly blocked
* Secure channel AAD binds role, transcript, and sequence number

For details, see `docs/threat_model.md`.

---

## Why This Exists

Most pairing protocols fail because they are:

* Implicit
* Over-flexible
* Under-documented
* Impossible to audit without folklore knowledge

TACCV exists to be:

* Readable
* Verifiable by inspection
* Honest about its limits

No hype. No magic. Just systems you can reason about.

---

## License

MIT License. See `LICENSE`.

Use responsibly.
