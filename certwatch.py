#!/usr/bin/env python3
"""
certwatch — TLS certificate watchdog: expiry, chain trust, and config checks.

Connects like a browser, parses the served certificate from its DER bytes
with the stdlib ssl module (no third-party crypto libraries), and reports:
expiry countdown, self-signed / untrusted-CA detection, weak keys, weak
signature algorithms, hostname/SAN mismatch, and deprecated TLS versions.

Zero external dependencies: Python 3.9+ standard library only.

Usage:
    python3 certwatch.py check github.com
    python3 certwatch.py check mail.internal.lan --port 993 --warn-days 14
    python3 certwatch.py watch hosts.txt --warn-days 21 --json report.json
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import socket
import ssl
import sys
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

__version__ = "1.1.0"

WEAK_SIGNATURES = {"sha1withrsaencryption", "sha1", "md5withrsa", "md5"}
MIN_RSA_BITS = 2048
MIN_EC_BITS = 224
DEPRECATED_TLS = {"TLSv1", "TLSv1.1"}


@dataclass
class CertReport:
    host: str
    port: int
    connected: bool = False
    error: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_left: Optional[int] = None
    self_signed: Optional[bool] = None
    untrusted: Optional[bool] = None
    hostname_ok: Optional[bool] = None
    signature_algorithm: Optional[str] = None
    key_bits: Optional[int] = None
    key_type: Optional[str] = None
    san: List[str] = field(default_factory=list)
    tls_version: Optional[str] = None
    findings: List[str] = field(default_factory=list)
    status: str = "unknown"       # ok | warn | crit | error

    def to_dict(self) -> dict:
        return vars(self)


# ---------------------------------------------------------------------------
# Certificate parsing (stdlib-only DER -> fields)
# ---------------------------------------------------------------------------

def parse_der_cert(der: bytes) -> dict:
    """Parse a DER certificate into a field dict using the stdlib.

    Strategy: wrap the DER bytes into a PEM, write to a temp file, and use
    ssl._test_decode_cert() — the stdlib's own certificate decoder. Works
    even for self-signed/expired certs (it never validates trust).
    """
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as tf:
        tf.write(pem)
        path = tf.name
    try:
        return ssl._ssl._test_decode_cert(path)
    finally:
        import os
        os.unlink(path)


def _name_cn(name_field) -> Optional[str]:
    """Extract commonName from the decoded name structure.

    _test_decode_cert returns names as a tuple of RDNs, each RDN being a
    tuple of (attribute, value) pairs — e.g. (('commonName', 'x'),).
    """
    if not name_field:
        return None
    try:
        for rdn in name_field:
            if isinstance(rdn, tuple) and len(rdn) == 2 and \
                    isinstance(rdn[0], str) and isinstance(rdn[1], str):
                key, value = rdn          # flat (attr, value) pair
                if key == "commonName":
                    return value
            else:                          # nested RDN tuple
                for key, value in rdn:
                    if key == "commonName":
                        return value
    except (TypeError, ValueError):
        return None
    return None


def _name_str(name_field) -> str:
    """Human-readable name: CN if present, else full rendering."""
    if not name_field:
        return ""
    cn = _name_cn(name_field)
    if cn:
        return cn
    parts = []
    try:
        for rdn in name_field:
            if isinstance(rdn, tuple) and len(rdn) == 2 and \
                    isinstance(rdn[0], str):
                parts.append(f"{rdn[0]}={rdn[1]}")
            else:
                for key, value in rdn:
                    parts.append(f"{key}={value}")
    except (TypeError, ValueError):
        return str(name_field)
    return ", ".join(parts)


def _parse_date(value: Optional[str]) -> Optional[dt.datetime]:
    """Parse ssl's 'notAfter' format: 'Jun  1 12:00:00 2027 GMT'."""
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Connection + analysis
# ---------------------------------------------------------------------------

def _connect(host: str, port: int, timeout: float, verify: bool):
    """Open a TLS connection. verify=True uses system CAs (strict)."""
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            return der, tls.version()


def analyze_cert(host: str, port: int = 443, timeout: float = 10.0,
                 warn_days: int = 30) -> CertReport:
    """Connect, pull the served certificate, and evaluate it."""
    rep = CertReport(host=host, port=port)

    # Pass 1: permissive — we want the raw cert even if it's invalid.
    try:
        der, tls_version = _connect(host, port, timeout, verify=False)
    except (socket.timeout, ConnectionRefusedError) as exc:
        rep.error = f"connection failed: {type(exc).__name__}"
        rep.status = "error"
        return rep
    except ssl.SSLError as exc:
        rep.error = f"TLS error: {exc.reason or exc}"
        rep.status = "error"
        return rep
    except OSError as exc:
        rep.error = f"socket error: {exc}"
        rep.status = "error"
        return rep

    if not der:
        rep.error = "no certificate served"
        rep.status = "error"
        return rep
    rep.connected = True
    rep.tls_version = tls_version

    # Parse fields from the DER bytes.
    try:
        cert = parse_der_cert(der)
    except Exception as exc:  # parser failure shouldn't kill the report
        rep.error = f"certificate parse failed: {exc}"
        rep.status = "error"
        return rep

    rep.subject = _name_str(cert.get("subject"))
    rep.issuer = _name_str(cert.get("issuer"))
    rep.signature_algorithm = (cert.get("signatureAlgorithm") or "").lower()
    exp = _parse_date(cert.get("notAfter"))
    nb = _parse_date(cert.get("notBefore"))
    if exp:
        rep.not_after = exp.isoformat()
        rep.days_left = (exp - dt.datetime.utcnow()).days
    if nb:
        rep.not_before = nb.isoformat()

    # SANs
    rep.san = sorted({v for t, v in cert.get("subjectAltName", ())
                      if t == "DNS"})

    # Hostname match — wildcard-aware, done manually since we control verify.
    import re as _re
    def _match(pattern: str, name: str) -> bool:
        pat = _re.escape(pattern).replace(r"\*", "[^.]*")
        return _re.fullmatch(pat, name) is not None
    candidates = rep.san or ([rep.subject] if rep.subject else [])
    rep.hostname_ok = any(_match(p, host) for p in candidates if p)
    if not rep.hostname_ok:
        rep.findings.append(
            f"hostname '{host}' not covered by certificate names "
            f"({', '.join(candidates[:4]) or 'none'})")

    # Pass 2: strict — does this chain validate against system CAs?
    trusted = None
    try:
        der2, _ = _connect(host, port, timeout, verify=True)
        trusted = True
    except ssl.SSLCertVerificationError as exc:
        trusted = False
        reason = getattr(exc, "verify_code", None)
        # Common codes: 18=self-signed, 10=expired, 62=hostname mismatch
        if reason == 18 or "self signed" in str(exc).lower() \
                or "self-signed" in str(exc).lower():
            rep.findings.append("certificate is self-signed (untrusted root)")
        elif reason == 10 or "expired" in str(exc).lower():
            rep.findings.append("certificate fails CA validation: EXPIRED")
        else:
            rep.findings.append(f"certificate fails CA validation: {exc.verify_message if hasattr(exc, 'verify_message') else exc}")
    except (ssl.SSLError, socket.timeout, OSError):
        trusted = None  # inconclusive — network flake, don't claim
    rep.untrusted = (trusted is False)
    rep.self_signed = (trusted is False and rep.issuer == rep.subject)

    # Key strength — decode from DER ourselves: look for the BIT STRING in
    # SPKI. Simpler: ssl decode gives no key info; approximate via signature
    # algorithm presence and note RSA size only when detectable.
    # We extract key size by parsing the SubjectPublicKeyInfo minimal DER.
    try:
        rep.key_bits, rep.key_type = _spki_key_info(der)
    except Exception:
        pass
    if rep.key_type == "RSA" and rep.key_bits and rep.key_bits < MIN_RSA_BITS:
        rep.findings.append(f"weak RSA key: {rep.key_bits} bits (< {MIN_RSA_BITS})")
    if rep.key_type == "EC" and rep.key_bits and rep.key_bits < MIN_EC_BITS:
        rep.findings.append(f"weak EC key: {rep.key_bits} bits")

    if rep.signature_algorithm in WEAK_SIGNATURES:
        rep.findings.append(f"weak signature algorithm: {rep.signature_algorithm}")

    if rep.tls_version in DEPRECATED_TLS:
        rep.findings.append(f"deprecated TLS version negotiated: {rep.tls_version}")

    # Expiry verdict
    if rep.days_left is not None:
        if rep.days_left < 0:
            rep.status = "crit"
            rep.findings.append(f"EXPIRED {-rep.days_left} days ago")
        elif rep.days_left <= warn_days:
            rep.status = "warn"
            rep.findings.append(f"expires in {rep.days_left} days "
                                f"(<= {warn_days}d warning window)")
        else:
            rep.status = "ok"

    if rep.status == "ok" and rep.findings:
        rep.status = "warn"
    return rep


# ---------------------------------------------------------------------------
# Minimal DER parsing for SubjectPublicKeyInfo key size/type
# ---------------------------------------------------------------------------

def _read_tlvs(data: bytes, offset: int = 0):
    """Yield (tag, value_bytes, next_offset) for TLVs at the top level."""
    i = offset
    while i < len(data):
        tag = data[i]
        i += 1
        # length (short/long form)
        length = data[i]
        i += 1
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(data[i:i + n], "big")
            i += n
        yield tag, data[i:i + length], i + length
        i = i + length


def _spki_key_info(der: bytes):
    """Extract (bits, type) from the SPKI inside a certificate DER.

    Navigation: Certificate -> tbsCertificate -> subjectPublicKeyInfo.
    All are SEQUENCEs; we walk them by index instead of full ASN.1.
    """
    def inner_tlvs(seq: bytes):
        return list(_read_tlvs(seq))

    # Certificate SEQUENCE
    cert_tlvs = inner_tlvs(der)
    for tag, val, _ in cert_tlvs:
        if tag == 0x30:  # tbsCertificate
            tbs_tlvs = inner_tlvs(val)
            idx = 0
            # optional [0] version
            if tbs_tlvs and tbs_tlvs[0][0] == 0xA0:
                idx = 1
            # serialNumber, signature, issuer, validity, subject, SPKI
            spki = tbs_tlvs[idx + 5]
            spki_inner = inner_tlvs(spki[1])
            # SPKI = SEQUENCE( AlgorithmIdentifier, BIT STRING )
            for atag, aval, _ in spki_inner:
                if atag == 0x30:  # AlgorithmIdentifier
                    alg_tlvs = inner_tlvs(aval)
                    oid = alg_tlvs[0][1] if alg_tlvs else b""
                    if oid.startswith(b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"):
                        key_type = "RSA"
                    elif oid.startswith(b"\x2a\x86\x48\xce\x3d"):
                        key_type = "EC"
                    else:
                        key_type = oid.hex()
                elif atag == 0x03:  # BIT STRING — the public key
                    key_data = aval[1:]  # skip unused-bits byte
                    if key_type == "RSA":
                        # RSA RSAPublicKey = SEQUENCE(modulus, exponent)
                        rsa_tlvs = inner_tlvs(key_data)
                        if rsa_tlvs and rsa_tlvs[0][0] == 0x30:
                            mod_tlvs = inner_tlvs(rsa_tlvs[0][1])
                            if mod_tlvs and mod_tlvs[0][0] == 0x02:
                                modulus = mod_tlvs[0][1]
                                bits = (len(modulus) - (1 if modulus[0] == 0 else 0)) * 8
                                return bits, "RSA"
                    elif key_type == "EC":
                        # Named curve: bit-length from point length (uncompressed)
                        return (len(key_data) - 1) * 4, "EC"
                    return None, key_type
            break
    return None, None


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_report(rep: CertReport) -> None:
    icon = {"ok": "✅", "warn": "⚠️ ", "crit": "❌", "error": "💥"}.get(rep.status, "•")
    print(f"{icon} {rep.host}:{rep.port} — {rep.status.upper()}")
    if rep.error:
        print(f"    error: {rep.error}")
    if rep.connected:
        if rep.subject:
            print(f"    subject:  {rep.subject}")
        if rep.issuer:
            print(f"    issuer:   {rep.issuer}")
        if rep.days_left is not None:
            print(f"    expiry:   {rep.not_after}  ({rep.days_left} days left)")
        print(f"    SANs:     {', '.join(rep.san[:6]) or '-'}")
        if rep.key_type:
            print(f"    key:      {rep.key_type} {rep.key_bits or '?'} bits")
        if rep.tls_version:
            print(f"    TLS:      {rep.tls_version}")
    for f in rep.findings:
        print(f"    ! {f}")


def print_summary(reports: List[CertReport]) -> None:
    ok = sum(1 for r in reports if r.status == "ok")
    warn = sum(1 for r in reports if r.status == "warn")
    crit = sum(1 for r in reports if r.status == "crit")
    err = sum(1 for r in reports if r.status == "error")
    print(f"\n{len(reports)} hosts: {ok} ok, {warn} warn, {crit} critical, {err} errors")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="certwatch",
        description="TLS certificate watchdog — expiry, self-signed, weak "
                    "keys, hostname coverage. Stdlib only.")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="inspect one host")
    c.add_argument("host")
    c.add_argument("--port", type=int, default=443)
    c.add_argument("--timeout", type=float, default=10.0)
    c.add_argument("--warn-days", type=int, default=30)

    w = sub.add_parser("watch", help="inspect many hosts from a file")
    w.add_argument("hostfile", help="file with host[:port] per line")
    w.add_argument("--warn-days", type=int, default=30)
    w.add_argument("--timeout", type=float, default=10.0)
    w.add_argument("--json", metavar="FILE", help="write report as JSON")

    p.add_argument("--version", action="version", version=f"certwatch {__version__}")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "check":
        rep = analyze_cert(args.host, args.port, args.timeout, args.warn_days)
        print_report(rep)
        return 0 if rep.status == "ok" else 1

    with open(args.hostfile, encoding="utf-8") as fh:
        entries = [ln.strip() for ln in fh
                   if ln.strip() and not ln.startswith("#")]
    reports: List[CertReport] = []
    for entry in entries:
        if entry.count(":") == 1:
            host, _, port = entry.partition(":")
            target, target_port = host, int(port)
        else:
            target, target_port = entry, 443
        rep = analyze_cert(target, target_port, args.timeout, args.warn_days)
        reports.append(rep)
        print_report(rep)

    print_summary(reports)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([r.to_dict() for r in reports], fh, indent=2)
        print(f"JSON written to {args.json}")

    return 0 if all(r.status == "ok" for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
