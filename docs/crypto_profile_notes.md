# Cryptographic Profiles

Profiles are versioned bundles of:
- Transcript labels
- Handshake labels
- Secure channel labels
- Minimum security level

Example:
- v41-pake
- v40-pake
- v35-pake

Profiles are ranked numerically and compared explicitly.

### Downgrade Protection
A peer proposing a lower-ranked profile than the minimum allowed is rejected.

This prevents:
- Silent security degradation
- Cross-version confusion
- “Best effort” crypto negotiation

Profiles are meant to be **boring and explicit**, not flexible.
