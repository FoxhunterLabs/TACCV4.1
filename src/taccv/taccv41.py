from __future__ import annotations
import argparse
import asyncio
import secrets
import sys

from taccv.util.deps import check_dependencies
from taccv.util.logging import configure_logging
from taccv.crypto.pake import normalize_password
from taccv.client.wsclient import WSClient
from taccv.client.errors import ProtocolError
from taccv.relay.app import build_relay_app

def security_self_check(logger):
    import sys as _sys
    import secrets as _secrets
    from taccv.crypto.primitives import b64d
    from taccv.protocol.profiles import profile_allowed

    checks = []
    checks.append(("Python >= 3.9", _sys.version_info >= (3, 9)))

    try:
        test = [_secrets.randbits(16) for _ in range(10)]
        checks.append(("Random source", all(x != 0 for x in test)))
    except Exception:
        checks.append(("Random source", False))

    for dep_name, fn in [
        ("SPAKE2", lambda: __import__("spake2")),
        ("Cryptography", lambda: __import__("cryptography")),
    ]:
        try:
            fn()
            checks.append((dep_name, True))
        except Exception:
            checks.append((dep_name, False))

    try:
        b64d("aW52YWxpZCBwYWRkaW5n")
        checks.append(("Base64 strict decode (valid)", True))
    except Exception:
        checks.append(("Base64 strict decode (valid)", False))

    try:
        b64d("invalid!@#$")
        checks.append(("Base64 strict decode (invalid)", False))
    except ValueError:
        checks.append(("Base64 strict decode (invalid)", True))

    checks.append(("Downgrade protection", profile_allowed("v41-pake") and profile_allowed("v40-pake") and not profile_allowed("v30-pake")))

    all_ok = all(ok for _, ok in checks)
    for name, ok in checks:
        (logger.info if ok else logger.error)("security_check", check=name, status=("OK" if ok else "FAILED"))
    if not all_ok:
        raise RuntimeError("Security self-check failed")
    logger.info("security_self_check_passed")
    return True

def main():
    ok, missing = check_dependencies()
    if not ok:
        print("ERROR: Missing dependencies:")
        for dep in missing:
            print(f"  - {dep}")
        print("\nInstall with:")
        print(f"pip install {' '.join(missing)}")
        sys.exit(1)

    logger = configure_logging()

    parser = argparse.ArgumentParser(description="TACCV4.1 Secure Pairing Protocol")
    subparsers = parser.add_subparsers(dest="command", required=True)

    relay_parser = subparsers.add_parser("relay", help="Run the untrusted relay server")
    relay_parser.add_argument("--host", default="127.0.0.1")
    relay_parser.add_argument("--port", type=int, default=8000)

    client_parser = subparsers.add_parser("client", help="Run a pairing client")
    client_parser.add_argument("--url", default="ws://localhost:8000")
    client_parser.add_argument("--session", required=True)
    client_parser.add_argument("--role", choices=["alice", "bob"], required=True)

    auth_group = client_parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--pin", help="6-12 digit PIN")
    auth_group.add_argument("--secret-b64", help="Base64 secret (≥16 bytes)")

    client_parser.add_argument("--message", default="Hello from TACCV4.1!")

    subparsers.add_parser("gen-secret", help="Generate a high-entropy secret")
    subparsers.add_parser("check", help="Run security self-check")

    args = parser.parse_args()

    if args.command == "check":
        security_self_check(logger)
        print("✓ Security self-check passed")
        return

    if args.command == "gen-secret":
        import base64
        secret = secrets.token_bytes(24)
        print(base64.b64encode(secret).decode("ascii"))
        return

    if args.command == "relay":
        security_self_check(logger)
        import uvicorn
        app = build_relay_app(logger)
        logger.info("starting_relay", host=args.host, port=args.port)
        uvicorn.run(app, host=args.host, port=args.port, log_config=None)
        return

    if args.command == "client":
        security_self_check(logger)
        password = normalize_password(args.pin, args.secret_b64)
        client = WSClient(url=args.url, session_code=args.session, role=args.role, password=password, logger=logger)

        print(f"Starting TACCV4.1 client as {args.role} in session {args.session}")
        print("Press Ctrl+C to exit")

        try:
            asyncio.run(client.run(args.message))
        except KeyboardInterrupt:
            logger.info("client_shutdown", reason="keyboard_interrupt")
            print("\nShutting down...")
        except ProtocolError as e:
            logger.error("protocol_error", error=str(e))
            print(f"Protocol error: {e}")
        except Exception as e:
            logger.error("unexpected_error", error=str(e))
            print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()

