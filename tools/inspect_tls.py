"""Decode a fingerprint into everything it contains, with names.

    python tools/inspect_tls.py spark1:eJy...            > out.json
    python tools/inspect_tls.py tools/captures/x.spark   > out.json
    python tools/inspect_tls.py profile/builtin/ios-safari-26.json

Prints JSON: every cipher suite, every extension with its parsed contents, the
HTTP/2 opening, the default headers, and the JA3 / JA4 / Akamai fingerprints.
"""
import base64
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
}
EXTENSIONS = {
    0: "server_name", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats",
    13: "signature_algorithms", 16: "application_layer_protocol_negotiation",
    18: "signed_certificate_timestamp", 21: "padding", 23: "extended_master_secret",
    27: "compress_certificate", 28: "record_size_limit", 34: "delegated_credentials",
    35: "session_ticket", 41: "pre_shared_key", 42: "early_data", 43: "supported_versions",
    45: "psk_key_exchange_modes", 50: "signature_algorithms_cert", 51: "key_share",
    57: "quic_transport_parameters", 17513: "application_settings (old)",
    17613: "application_settings", 65037: "encrypted_client_hello", 65281: "renegotiation_info",
}
GROUPS = {
    29: "x25519", 23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 30: "x448",
    4588: "X25519MLKEM768 (post-quantum hybrid)", 25497: "X25519Kyber768Draft00",
    256: "ffdhe2048", 257: "ffdhe3072",
}
SIGALGS = {
    0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384", 0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512",
    0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
    0x0201: "rsa_pkcs1_sha1", 0x0203: "ecdsa_sha1", 0x0807: "ed25519", 0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256", 0x080A: "rsa_pss_pss_sha384", 0x080B: "rsa_pss_pss_sha512",
}
VERSIONS = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1", 0x0301: "TLS 1.0"}
CERT_COMP = {1: "zlib", 2: "brotli", 3: "zstd"}
H2_SETTINGS = {
    1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS",
    4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE",
    8: "ENABLE_CONNECT_PROTOCOL", 9: "NO_RFC7540_PRIORITIES",
}


def grease(v):
    return (v & 0x0F0F) == 0x0A0A


def u16s(b):
    return [struct.unpack_from("!H", b, i)[0] for i in range(0, len(b) - 1, 2)]


def hx(v):
    return f"0x{v:04x}"


def named(v, table):
    return {"id": v, "hex": hx(v), "name": "GREASE (random placeholder)" if grease(v) else table.get(v, "unknown")}


def load(arg):
    if Path(arg).is_file():
        text = Path(arg).read_text().strip()
    else:
        text = arg.strip()
    if text.startswith("spark1:"):
        body = text[7:]
        return json.loads(zlib.decompress(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))), "spark1 token"
    return json.loads(text), "profile json"


def parse_extension(typ, d):
    if typ == 0:
        names, p = [], 2
        while p + 3 <= len(d):
            n = struct.unpack_from("!H", d, p + 1)[0]
            names.append(d[p + 3:p + 3 + n].decode())
            p += 3 + n
        return {"server_names": names, "note": "replaced with the real host on every request"}
    if typ == 10:
        return {"groups": [named(g, GROUPS) for g in u16s(d[2:])]}
    if typ == 11:
        return {"formats": [{0: "uncompressed"}.get(x, x) for x in d[1:1 + d[0]]]}
    if typ in (13, 50):
        return {"algorithms": [named(s, SIGALGS) for s in u16s(d[2:])]}
    if typ == 16:
        out, p, blob = [], 0, d[2:]
        while p < len(blob):
            out.append(blob[p + 1:p + 1 + blob[p]].decode())
            p += 1 + blob[p]
        return {"protocols": out}
    if typ == 5:
        return {"type": "OCSP" if d and d[0] == 1 else d.hex()}
    if typ == 27:
        return {"algorithms": [CERT_COMP.get(a, a) for a in u16s(d[1:1 + d[0]])]}
    if typ == 28:
        return {"limit": struct.unpack("!H", d)[0]}
    if typ == 43:
        return {"versions": [named(v, VERSIONS) for v in u16s(d[1:1 + d[0]])]}
    if typ == 45:
        return {"modes": [{0: "psk_ke", 1: "psk_dhe_ke"}.get(m, m) for m in d[1:1 + d[0]]]}
    if typ == 51:
        shares, p, blob = [], 0, d[2:]
        while p + 4 <= len(blob):
            g, n = struct.unpack_from("!HH", blob, p)
            shares.append(dict(named(g, GROUPS), key_bytes=n))
            p += 4 + n
        return {"shares": shares, "note": "public keys are generated fresh on every connection"}
    if typ == 65281:
        return {"renegotiated_connection": d[1:].hex() or "(empty: initial handshake)"}
    if typ == 21:
        return {"padding_bytes": len(d)}
    if typ == 17613 or typ == 17513:
        out, p, blob = [], 0, d[2:]
        while p < len(blob):
            out.append(blob[p + 1:p + 1 + blob[p]].decode())
            p += 1 + blob[p]
        return {"protocols": out}
    if typ == 65037:
        return {"note": "GREASE ECH: random payload, regenerated per connection", "bytes": len(d)}
    if not d:
        return {"note": "empty (presence is the signal)"}
    return {"raw_hex": d.hex()}


def inspect_hello(raw):
    body = raw[5:]
    rec_ver = struct.unpack_from("!H", raw, 1)[0]
    hello_ver = struct.unpack_from("!H", body, 4)[0]
    p = 6 + 32
    sid = body[p]
    p += 1 + sid
    n = struct.unpack_from("!H", body, p)[0]
    ciphers = u16s(body[p + 2:p + 2 + n])
    p += 2 + n
    comp = list(body[p + 1:p + 1 + body[p]])
    p += 1 + body[p]
    end = p + 2 + struct.unpack_from("!H", body, p)[0]
    p += 2
    exts = []
    while p + 4 <= end:
        typ, ln = struct.unpack_from("!HH", body, p)
        d = bytes(body[p + 4:p + 4 + ln])
        e = named(typ, EXTENSIONS)
        e["length"] = ln
        if not grease(typ):
            e.update(parse_extension(typ, d))
        exts.append(e)
        p += 4 + ln
    return {
        "record_version": named(rec_ver, VERSIONS),
        "client_version": named(hello_ver, VERSIONS),
        "random": "32 bytes, fresh every connection",
        "session_id_length": sid,
        "cipher_suites": [named(c, CIPHERS) for c in ciphers],
        "compression_methods": ["null" if c == 0 else c for c in comp],
        "extensions": exts,
        "total_bytes": len(raw),
    }, ciphers, exts


def fingerprints(ciphers, exts):
    c = [x for x in ciphers if not grease(x)]
    e = [x["id"] for x in exts if not grease(x["id"])]
    by = {x["id"]: x for x in exts}
    groups = [g["id"] for g in by.get(10, {}).get("groups", []) if not grease(g["id"])]
    ja3 = "{},{},{},{},{}".format(
        771, "-".join(map(str, c)), "-".join(map(str, e)), "-".join(map(str, groups)),
        "-".join("0" if f == "uncompressed" else str(f) for f in by.get(11, {}).get("formats", [])))
    versions = [v["id"] for v in by.get(43, {}).get("versions", []) if not grease(v["id"])]
    ver = {0x0304: "13", 0x0303: "12"}.get(max(versions) if versions else 0x0303, "00")
    alpn = (by.get(16, {}).get("protocols") or ["00"])[0]
    sigs = [s["hex"][2:] for s in by.get(13, {}).get("algorithms", [])]
    ja4_a = f"t{ver}{'d' if 0 in by else 'i'}{len(c):02d}{len(e):02d}{alpn[0]}{alpn[-1]}"
    ja4_b = hashlib.sha256(",".join(sorted(f"{x:04x}" for x in c)).encode()).hexdigest()[:12]
    ext_part = ",".join(sorted(f"{x:04x}" for x in e if x not in (0, 16)))
    ja4_c = hashlib.sha256((ext_part + "_" + ",".join(sigs)).encode()).hexdigest()[:12]
    return {
        "ja3": ja3,
        "ja3_hash": hashlib.md5(ja3.encode()).hexdigest(),
        "ja4": f"{ja4_a}_{ja4_b}_{ja4_c}",
        "note": "JA3 changes per connection for clients that shuffle extensions; JA4 doesn't",
    }


def main(arg):
    p, source = load(arg)
    raw = base64.b64decode(p["tls"]["raw_client_hello"])
    hello, ciphers, exts = inspect_hello(raw)
    out = {
        "name": p.get("name"),
        "description": p.get("description"),
        "source": source,
        "fingerprints": fingerprints(ciphers, exts),
        "tls": {"permute_extension_order": bool(p["tls"].get("permute")), **hello},
    }
    h2 = p.get("http2")
    if h2:
        pseudo = h2.get("pseudo_order") or []
        settings = [{"id": s["id"], "name": H2_SETTINGS.get(s["id"], "unknown"), "value": s["value"]}
                    for s in h2.get("settings", [])]
        out["http2"] = {
            "akamai": "{}|{}|0|{}".format(
                ";".join(f'{s["id"]}:{s["value"]}' for s in settings),
                h2.get("connection_window_update", 0), ",".join(x[1] for x in pseudo)),
            "settings_in_order": settings,
            "connection_window_update": h2.get("connection_window_update"),
            "pseudo_header_order": pseudo,
            "headers_frame_priority": h2.get("header_priority") or "none sent",
        }
    out["default_headers"] = p.get("headers") or []
    out["header_order"] = p.get("header_order") or []
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
