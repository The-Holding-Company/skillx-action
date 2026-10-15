#!/usr/bin/env python3
"""skillx — sign and verify agent skills (SKILL.md) per SPEC.md v0.1.

Commands:
  skillx sign   --key <pem> --kid <did-url> [--url <canonical-url>] <SKILL.md>
  skillx verify [--jwk <jwk.json>] [--sig <path-or-url>] [--scan] <path-or-url>
  skillx keygen --out <pem> [--pub-jwk <jwk.json>]

Signing is offline. Verification resolves the signer's did:web DID document
over HTTPS unless a local --jwk is supplied. --scan additionally runs
prompt-detect over the skill content when available.
"""

import argparse
import base64
import hashlib
import hmac as _hmac
import json
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature

SIG_TYP = "application/vnd.skillx.sig.v1+jws"
USER_AGENT = "skillx/0.1 (+https://username.md/SKILL.md)"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read()


def read_source(src: str) -> bytes:
    if src.startswith("http://"):
        sys.exit("skillx: refusing plaintext http:// source")
    if src.startswith("https://"):
        return fetch(src)
    return Path(src).read_bytes()


def did_web_to_did_json_url(did: str) -> str:
    if not did.startswith("did:web:"):
        sys.exit(f"skillx: unsupported DID method in kid: {did}")
    parts = did[len("did:web:"):].split(":")
    host = urllib.parse.unquote(parts[0])
    if len(parts) == 1:
        return f"https://{host}/.well-known/did.json"
    path = "/".join(urllib.parse.unquote(p) for p in parts[1:])
    return f"https://{host}/{path}/did.json"


def jwk_to_public_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        sys.exit("skillx: kid resolved to a non-P-256 key; v0.1 requires ES256")
    x = int.from_bytes(b64u_dec(jwk["x"]), "big")
    y = int.from_bytes(b64u_dec(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def public_key_to_jwk(pub: ec.EllipticCurvePublicKey) -> dict:
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(nums.x.to_bytes(32, "big")),
        "y": b64u(nums.y.to_bytes(32, "big")),
    }


def cmd_keygen(args):
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    out = Path(args.out)
    out.touch(mode=0o600, exist_ok=True)
    out.write_bytes(pem)
    out.chmod(0o600)
    jwk = public_key_to_jwk(key.public_key())
    if args.pub_jwk:
        Path(args.pub_jwk).write_text(json.dumps(jwk, indent=2) + "\n")
    print(f"private key: {out}  (mode 0600 — store in OpenBao, do not commit)")
    print(f"public JWK: {json.dumps(jwk)}")


def cmd_sign(args):
    artifact = Path(args.skill).read_bytes()
    digest = hashlib.sha256(artifact).hexdigest()

    name = None
    m = re.search(rb"^name:\s*(\S+)\s*$", artifact, re.MULTILINE)
    if m:
        name = m.group(1).decode()

    key = serialization.load_pem_private_key(
        Path(args.key).read_bytes(), password=None
    )
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        sys.exit("skillx: --key must be an EC P-256 private key")

    header = {"alg": "ES256", "typ": SIG_TYP, "kid": args.kid}
    payload = {
        "v": 1,
        "sha256": digest,
        "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if name:
        payload["name"] = name
    if args.url:
        payload["url"] = args.url

    signing_input = (
        b64u(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64u(json.dumps(payload, separators=(",", ":")).encode())
    )
    der = key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    jws = signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    sig_path = Path(args.skill + ".sig")
    sig_path.write_text(jws + "\n")
    print(f"signed: {args.skill}")
    print(f"  sha256: {digest}")
    print(f"  kid:    {args.kid}")
    print(f"  sig:    {sig_path}")


def find_scanner() -> str | None:
    found = shutil.which("prompt-detect")
    if found:
        return found
    for candidate in ("/usr/local/bin/prompt-detect",
                      str(Path.home() / "bin" / "prompt-detect")):
        if Path(candidate).exists():
            return candidate
    return None


def run_scan(artifact: bytes) -> str:
    # Note: every SKILL.md is prompt content by nature, so prompt-detect will
    # usually score it. The useful signal is the report itself (templates,
    # API-call patterns, embedded instructions) — read it, don't threshold it.
    scanner = find_scanner()
    if not scanner:
        return "scan: prompt-detect not installed, skipped"
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".md") as tf:
        tf.write(artifact)
        tf.flush()
        proc = subprocess.run(
            [scanner, tf.name], capture_output=True, timeout=60
        )
    report = proc.stdout.decode(errors="replace").strip() or proc.stderr.decode(
        errors="replace"
    ).strip()
    return f"scan report (prompt-detect exit {proc.returncode}):\n{report}"


def cmd_verify(args):
    artifact = read_source(args.skill)
    sig_src = args.sig or args.skill + ".sig"
    try:
        jws = read_source(sig_src).decode().strip()
    except (FileNotFoundError, urllib.error.HTTPError):
        print(f"UNSIGNED: no signature at {sig_src}")
        sys.exit(2)
    # Some static hosts serve their landing page as a 200 fallback for missing
    # paths; an HTML body where the .sig should be means "no signature", not
    # "corrupted signature".
    if jws[:1] == "<":
        print(f"UNSIGNED: no signature at {sig_src} (got an HTML fallback page)")
        sys.exit(2)

    try:
        h_b64, p_b64, s_b64 = jws.split(".")
    except ValueError:
        sys.exit("INVALID: signature is not a compact JWS")
    header = json.loads(b64u_dec(h_b64))
    payload = json.loads(b64u_dec(p_b64))

    if header.get("alg") != "ES256" or header.get("typ") != SIG_TYP:
        sys.exit(f"INVALID: unexpected header alg/typ: {header}")
    kid = header.get("kid", "")

    if args.jwk:
        jwk = json.loads(Path(args.jwk).read_text())
    else:
        did = kid.split("#")[0]
        did_doc = json.loads(fetch(did_web_to_did_json_url(did)))
        methods = {m.get("id"): m for m in did_doc.get("verificationMethod", [])}
        if kid not in methods:
            sys.exit(f"INVALID: kid {kid} not present in DID document for {did}")
        jwk = methods[kid]["publicKeyJwk"]
    pub = jwk_to_public_key(jwk)

    sig = b64u_dec(s_b64)
    der = encode_dss_signature(
        int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    )
    try:
        pub.verify(der, f"{h_b64}.{p_b64}".encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        sys.exit("INVALID: JWS signature verification failed")

    digest = hashlib.sha256(artifact).hexdigest()
    if not _hmac.compare_digest(digest, payload.get("sha256", "")):
        sys.exit(
            f"INVALID: artifact digest mismatch\n  artifact:  {digest}\n"
            f"  signature: {payload.get('sha256')}"
        )

    print("VERIFIED")
    print(f"  skill:     {payload.get('name', '(unnamed)')}")
    print(f"  publisher: {kid}")
    print(f"  sha256:    {digest}")
    print(f"  signed_at: {payload.get('signed_at')}")
    if args.scan:
        print(run_scan(artifact))


def cmd_install(args):
    if not args.skill.startswith("https://"):
        sys.exit("skillx: install requires an https:// URL")
    artifact = read_source(args.skill)

    verified = False
    try:
        cmd_verify(
            argparse.Namespace(
                skill=args.skill, sig=args.sig, jwk=None, scan=True
            )
        )
        verified = True
    except SystemExit as e:
        if e.code == 2:  # unsigned
            print("WARNING: skill is UNSIGNED — publisher cannot be verified.")
            if not args.allow_unsigned:
                sys.exit("skillx: refusing to install (use --allow-unsigned to override)")
        else:  # invalid signature — never install
            raise

    m = re.search(rb"^name:\s*(\S+)\s*$", artifact, re.MULTILINE)
    name = args.name or (m.group(1).decode() if m else None)
    if not name:
        sys.exit("skillx: cannot determine skill name; pass --name")
    dest = Path.home() / ".claude" / "skills" / name
    if (dest / "SKILL.md").exists() and not args.force:
        sys.exit(f"skillx: {dest}/SKILL.md exists (use --force to overwrite)")
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "SKILL.md").write_bytes(artifact)
    print(f"installed: {dest}/SKILL.md ({'verified' if verified else 'UNSIGNED'})")


def main():
    ap = argparse.ArgumentParser(prog="skillx", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="generate an ES256 signing keypair")
    kg.add_argument("--out", required=True, help="private key PEM output path")
    kg.add_argument("--pub-jwk", help="write public JWK JSON here")
    kg.set_defaults(fn=cmd_keygen)

    sg = sub.add_parser("sign", help="sign a SKILL.md, writing SKILL.md.sig")
    sg.add_argument("skill")
    sg.add_argument("--key", required=True, help="EC P-256 private key PEM")
    sg.add_argument("--kid", required=True, help="did:web DID URL with fragment")
    sg.add_argument("--url", help="canonical distribution URL")
    sg.set_defaults(fn=cmd_sign)

    vf = sub.add_parser("verify", help="verify a SKILL.md against its .sig")
    vf.add_argument("skill", help="path or https:// URL")
    vf.add_argument("--sig", help="signature path/URL (default: <skill>.sig)")
    vf.add_argument("--jwk", help="verify against a local JWK instead of did:web")
    vf.add_argument("--scan", action="store_true", help="also run prompt-detect")
    vf.set_defaults(fn=cmd_verify)

    ins = sub.add_parser(
        "install", help="verify + scan + install a skill into ~/.claude/skills/"
    )
    ins.add_argument("skill", help="https:// URL of the SKILL.md")
    ins.add_argument("--sig", help="signature URL (default: <skill>.sig)")
    ins.add_argument("--name", help="skill directory name (default: frontmatter name)")
    ins.add_argument("--allow-unsigned", action="store_true")
    ins.add_argument("--force", action="store_true")
    ins.set_defaults(fn=cmd_install)

    args = ap.parse_args()
    # Network and parse failures below this line are environmental, not
    # signature verdicts: exit 1 with one clean line (never a traceback), and
    # let CI map a fetch failure to a failed job — fail closed.
    try:
        args.fn(args)
    except urllib.error.HTTPError as e:
        hint = ""
        if "infinite loop" in str(e).lower():
            hint = (
                " — the server redirects this URL to itself; the file likely"
                " does not exist and the site misroutes 404s"
            )
        reason = " ".join(str(e.reason).split())
        sys.exit(f"skillx: ERROR fetching {e.url}: HTTP {e.code} {reason}{hint}")
    except urllib.error.URLError as e:
        sys.exit(f"skillx: ERROR fetching: {e.reason}")
    except TimeoutError:
        sys.exit("skillx: ERROR: network timeout after 15s")
    except json.JSONDecodeError as e:
        sys.exit(f"skillx: ERROR: expected JSON but got something else ({e.msg})")


if __name__ == "__main__":
    main()
