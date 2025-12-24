# Threat Model

## Adversary Capabilities
We assume an attacker may:
- Fully control the relay server
- Observe, replay, delay, or drop packets
- Initiate parallel sessions
- Attempt downgrade attacks
- Attempt active MITM during pairing

We do NOT assume:
- Endpoint compromise
- Side-channel resistant hardware
- Constant-time execution across the entire runtime

## Security Goals
TACCV4.1 aims to guarantee:
- Mutual authentication via PAKE
- Session key secrecy against passive and active attackers
- Explicit key confirmation
- Transcript-bound handshake
- Replay resistance
- Downgrade protection via profile ranking

## Explicit Non-Goals
- Post-compromise security
- Deniability
- Anonymity
- Forward secrecy beyond the PAKE + X25519 exchange
- Resistance to nation-state hardware attacks

This protocol favors **correctness over cleverness**.
