# Non-Goals, Risks, and Warnings

## Reference Implementation Warning
This code is NOT production-hardened.

Known limitations:
- Not constant-time
- No formal verification
- No hardened memory zeroization
- Python runtime assumptions
- Limited DoS protection

## Design Tradeoffs
We intentionally chose:
- Explicit state machines over implicit flows
- Verbose transcripts over compact ones
- Human-auditable logic over maximum performance

## If You Deploy This Anyway
You accept:
- Cryptographic risk
- Operational risk
- Legal and compliance risk

TACCV exists to be **understood**, not blindly trusted.
