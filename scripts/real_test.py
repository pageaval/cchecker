#!/usr/bin/env python3
from __future__ import annotations

import base64
import concurrent.futures
import dataclasses
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

URLS_FILE = Path(os.getenv("URLS_FILE", "urls.txt"))
XRAY_BIN = os.getenv("XRAY_BIN", "./xray")
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "output"))

WORKERS = max(1, min(int(os.getenv("WORKERS", "6")), 12))
STARTUP_TIMEOUT = float(os.getenv("STARTUP_TIMEOUT", "3"))
PROBE_TIMEOUT = int(os.getenv("PROBE_TIMEOUT", "10"))
DOWNLOAD_TIMEOUT = int(os.getenv("DOWNLOAD_TIMEOUT", "20"))
MAX_CONFIGS = int(os.getenv("MAX_CONFIGS", "0"))  # 0 = no limit
BATCH_SIZE = max(1, int(os.getenv("BATCH_SIZE", "40")))
BATCH_PAUSE_SECONDS = max(0, int(os.getenv("BATCH_PAUSE_SECONDS", "15")))

PROBE_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
]
IP_URLS = [
    "https://api.ipify.org",
    "https://icanhazip.com",
]

# A config is added to output/iran.txt when it can reach at least
# IRAN_MIN_SUCCESSES of these destinations through the VLESS tunnel.
IRAN_PROBE_URLS = [
    url.strip()
    for url in os.getenv(
        "IRAN_PROBE_URLS",
        "https://www.irnic.ir/,https://www.shaparak.ir/,https://www.isna.ir/",
    ).split(",")
    if url.strip()
]
IRAN_MIN_SUCCESSES = max(1, int(os.getenv("IRAN_MIN_SUCCESSES", "2")))

SUPPORTED_NETWORKS = {
    "tcp", "raw", "ws", "grpc", "httpupgrade", "xhttp", "splithttp"
}


@dataclasses.dataclass
class TestResult:
    config: str
    ok: bool
    latency_ms: int | None
    exit_ip: str | None
    reason: str
    source: str
    iran_ok: bool = False
    iran_successes: int = 0
    iran_checked: int = 0


def qfirst(qs: dict[str, list[str]], *keys: str, default: str = "") -> str:
    for key in keys:
        values = qs.get(key)
        if values:
            return values[0]
    return default


def as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def fetch_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "github-real-vless-checker/1.0",
            "Accept": "*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as response:
        return response.read().decode("utf-8", errors="replace")


def maybe_decode_base64(text: str) -> str:
    stripped = "".join(text.strip().split())
    if "://" in text:
        return text
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = stripped + "=" * (-len(stripped) % 4)
            decoded = decoder(padded).decode("utf-8", errors="strict")
            if "://" in decoded:
                return decoded
        except Exception:
            pass
    return text


def extract_vless(text: str) -> list[str]:
    text = maybe_decode_base64(text)
    found: list[str] = []
    for line in text.replace("\r", "\n").splitlines():
        line = line.strip()
        if line.startswith("vless://"):
            found.append(line)
    # Also catch embedded URIs inside JSON/plain text.
    found.extend(re.findall(r'vless://[^\s"\'<>]+', text))
    return list(dict.fromkeys(found))


def normalize_network(value: str) -> str:
    value = (value or "tcp").lower()
    if value == "splithttp":
        return "xhttp"
    if value not in SUPPORTED_NETWORKS:
        raise ValueError(f"unsupported network: {value}")
    # Current Xray accepts tcp; raw is its newer name.
    return value


def build_xray_config(uri: str, socks_port: int) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(uri)
    if parsed.scheme.lower() != "vless":
        raise ValueError("not a VLESS URI")
    if not parsed.username:
        raise ValueError("missing UUID")
    if not parsed.hostname or parsed.port is None:
        raise ValueError("missing host or port")

    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    network = normalize_network(qfirst(qs, "type", default="tcp"))
    security = qfirst(qs, "security", default="none").lower()
    flow = qfirst(qs, "flow")
    encryption = qfirst(qs, "encryption", default="none") or "none"

    user: dict[str, Any] = {
        "id": urllib.parse.unquote(parsed.username),
        "encryption": encryption,
    }
    if flow:
        user["flow"] = flow

    stream: dict[str, Any] = {
        "network": network,
        "security": security if security in {"tls", "reality"} else "none",
    }

    host_header = qfirst(qs, "host")
    path = urllib.parse.unquote(qfirst(qs, "path", default="/"))
    sni = qfirst(qs, "sni", "serverName", default=host_header or parsed.hostname)
    fingerprint = qfirst(qs, "fp", "fingerprint", default="chrome")
    alpn_raw = qfirst(qs, "alpn")
    alpn = [x.strip() for x in urllib.parse.unquote(alpn_raw).split(",") if x.strip()]

    if security == "tls":
        tls: dict[str, Any] = {
            "serverName": sni,
            "allowInsecure": as_bool(qfirst(qs, "allowInsecure")),
        }
        if fingerprint:
            tls["fingerprint"] = fingerprint
        if alpn:
            tls["alpn"] = alpn
        stream["tlsSettings"] = tls

    elif security == "reality":
        public_key = qfirst(qs, "pbk", "publicKey")
        short_id = qfirst(qs, "sid", "shortId")
        if not public_key:
            raise ValueError("REALITY public key (pbk) is missing")
        reality: dict[str, Any] = {
            "serverName": sni,
            "fingerprint": fingerprint or "chrome",
            "publicKey": public_key,
            "shortId": short_id,
            "spiderX": urllib.parse.unquote(qfirst(qs, "spx", "spiderX", default="/")),
        }
        stream["realitySettings"] = reality

    if network == "ws":
        headers: dict[str, str] = {}
        if host_header:
            headers["Host"] = host_header
        stream["wsSettings"] = {
            "path": path or "/",
            "headers": headers,
        }

    elif network == "grpc":
        service_name = urllib.parse.unquote(
            qfirst(qs, "serviceName", default=path.lstrip("/"))
        )
        grpc: dict[str, Any] = {
            "serviceName": service_name,
            "multiMode": qfirst(qs, "mode").lower() == "multi",
        }
        authority = qfirst(qs, "authority")
        if authority:
            grpc["authority"] = authority
        stream["grpcSettings"] = grpc

    elif network == "httpupgrade":
        headers = {}
        if host_header:
            headers["Host"] = host_header
        stream["httpupgradeSettings"] = {
            "path": path or "/",
            "host": host_header,
            "headers": headers,
        }

    elif network == "xhttp":
        xhttp: dict[str, Any] = {
            "path": path or "/",
            "host": host_header,
        }
        mode = qfirst(qs, "mode")
        if mode:
            xhttp["mode"] = mode
        stream["xhttpSettings"] = xhttp

    elif network in {"tcp", "raw"}:
        header_type = qfirst(qs, "headerType", default="none").lower()
        if header_type and header_type != "none":
            stream["tcpSettings"] = {"header": {"type": header_type}}

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "local-socks",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": True,
            },
        }],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": parsed.hostname,
                        "port": parsed.port,
                        "users": [user],
                    }]
                },
                "streamSettings": stream,
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {},
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{
                "type": "field",
                "inboundTag": ["local-socks"],
                "outboundTag": "proxy",
            }],
        },
    }


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(port: int, process: subprocess.Popen[str]) -> bool:
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.08)
    return False


def curl_via_socks(port: int, url: str, body: bool = False) -> tuple[bool, str, int]:
    fmt = "%{http_code}"
    command = [
        "curl", "--silent", "--show-error", "--location",
        "--proxy", f"socks5h://127.0.0.1:{port}",
        "--connect-timeout", str(min(7, PROBE_TIMEOUT)),
        "--max-time", str(PROBE_TIMEOUT),
        "--retry", "0",
    ]
    if body:
        command += [url]
    else:
        command += ["--output", "/dev/null", "--write-out", fmt, url]

    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True)
    elapsed = int((time.monotonic() - started) * 1000)
    value = result.stdout.strip()
    if result.returncode != 0:
        return False, (result.stderr.strip() or f"curl exit {result.returncode}"), elapsed
    return True, value, elapsed


def valid_ip(value: str) -> str | None:
    candidate = value.strip().splitlines()[0] if value.strip() else ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def test_iran_access(port: int) -> tuple[bool, int, int, str]:
    """
    Test access to Iranian destinations through the already-running tunnel.
    HTTP 200-399 counts as success. We use GET instead of HEAD because
    some sites reject HEAD requests.
    """
    successes = 0
    checked = 0
    details: list[str] = []

    for url in IRAN_PROBE_URLS:
        checked += 1
        command = [
            "curl", "--silent", "--show-error", "--location",
            "--proxy", f"socks5h://127.0.0.1:{port}",
            "--connect-timeout", str(min(7, PROBE_TIMEOUT)),
            "--max-time", str(PROBE_TIMEOUT),
            "--output", "/dev/null",
            "--write-out", "%{http_code}",
            "--user-agent", "Mozilla/5.0 VLESS-Iran-Access-Checker/1.0",
            url,
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        code = result.stdout.strip()

        if result.returncode == 0 and code.isdigit() and 200 <= int(code) < 400:
            successes += 1
            details.append(f"{url}=HTTP {code}")
        else:
            error = result.stderr.strip() or f"HTTP {code or '000'}"
            details.append(f"{url}={error}")

    ok = successes >= min(IRAN_MIN_SUCCESSES, checked)
    return ok, successes, checked, "; ".join(details)

def test_one(item: tuple[str, str]) -> TestResult:
    uri, source = item
    port = free_port()
    process: subprocess.Popen[str] | None = None

    try:
        config = build_xray_config(uri, port)
        with tempfile.TemporaryDirectory(prefix="vless-check-") as temp:
            config_path = Path(temp) / "config.json"
            log_path = Path(temp) / "xray.log"
            config_path.write_text(
                json.dumps(config, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            syntax = subprocess.run(
                [XRAY_BIN, "run", "-test", "-config", str(config_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if syntax.returncode != 0:
                reason = (syntax.stderr or syntax.stdout).strip()[-600:]
                return TestResult(uri, False, None, None, f"config rejected: {reason}", source)

            log_file = log_path.open("w", encoding="utf-8")
            process = subprocess.Popen(
                [XRAY_BIN, "run", "-config", str(config_path)],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
            )

            if not wait_for_port(port, process):
                log_file.close()
                log = log_path.read_text(encoding="utf-8", errors="replace")[-600:]
                return TestResult(uri, False, None, None, f"Xray did not start: {log}", source)

            best_latency: int | None = None
            probe_ok = False
            probe_error = "no probe succeeded"

            for probe in PROBE_URLS:
                ok, value, elapsed = curl_via_socks(port, probe, body=False)
                if ok and value in {"200", "204"}:
                    probe_ok = True
                    best_latency = elapsed if best_latency is None else min(best_latency, elapsed)
                    break
                probe_error = value

            if not probe_ok:
                return TestResult(uri, False, best_latency, None, f"tunnel probe failed: {probe_error}", source)

            exit_ip = None
            ip_error = ""
            for ip_url in IP_URLS:
                ok, value, elapsed = curl_via_socks(port, ip_url, body=True)
                if ok:
                    exit_ip = valid_ip(value)
                    if exit_ip:
                        best_latency = elapsed if best_latency is None else min(best_latency, elapsed)
                        break
                ip_error = value

            if not exit_ip:
                return TestResult(uri, False, best_latency, None, f"exit IP check failed: {ip_error}", source)

            iran_ok, iran_successes, iran_checked, iran_details = test_iran_access(port)

            reason = "real traffic passed"
            if iran_ok:
                reason += f"; Iran access passed {iran_successes}/{iran_checked}"
            else:
                reason += f"; Iran access failed {iran_successes}/{iran_checked}: {iran_details}"

            return TestResult(
                uri,
                True,
                best_latency,
                exit_ip,
                reason,
                source,
                iran_ok=iran_ok,
                iran_successes=iran_successes,
                iran_checked=iran_checked,
            )

    except subprocess.TimeoutExpired:
        return TestResult(uri, False, None, None, "Xray config validation timed out", source)
    except Exception as exc:
        return TestResult(uri, False, None, None, f"{type(exc).__name__}: {exc}", source)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def read_urls() -> list[str]:
    if not URLS_FILE.exists():
        raise SystemExit(f"{URLS_FILE} does not exist")
    return [
        line.strip()
        for line in URLS_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def main() -> int:
    if not Path(XRAY_BIN).exists():
        raise SystemExit(f"Xray binary not found: {XRAY_BIN}")
    if shutil.which("curl") is None:
        raise SystemExit("curl is required")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    items: list[tuple[str, str]] = []
    seen: set[str] = set()
    source_errors: list[dict[str, str]] = []

    for url in read_urls():
        print(f"Downloading {url}", flush=True)
        try:
            configs = extract_vless(fetch_text(url))
            print(f"  found {len(configs)} VLESS configs", flush=True)
            for config in configs:
                fingerprint = hashlib.sha256(config.encode()).hexdigest()
                if fingerprint not in seen:
                    seen.add(fingerprint)
                    items.append((config, url))
        except Exception as exc:
            source_errors.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
            print(f"  source failed: {exc}", flush=True)

    if MAX_CONFIGS > 0:
        items = items[:MAX_CONFIGS]

    results: list[TestResult] = []
    total = len(items)
    print(f"Testing {total} unique configs with {WORKERS} workers", flush=True)

    completed_count = 0
    batches = [
        items[index:index + BATCH_SIZE]
        for index in range(0, len(items), BATCH_SIZE)
    ]
    total_batches = len(batches)

    print(
        f"Created {total_batches} batches with up to {BATCH_SIZE} configs each",
        flush=True,
    )

    for batch_number, batch_items in enumerate(batches, start=1):
        print("=" * 72, flush=True)
        print(
            f"Starting batch {batch_number}/{total_batches}: "
            f"{len(batch_items)} configs, {WORKERS} workers",
            flush=True,
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = {executor.submit(test_one, item): item for item in batch_items}

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:
                    config, source = futures[future]
                    result = TestResult(
                        config=config,
                        ok=False,
                        latency_ms=None,
                        exit_ip=None,
                        reason=f"Unhandled worker error: {type(exc).__name__}: {exc}",
                        source=source,
                    )

                results.append(result)
                completed_count += 1
                status = "OK" if result.ok else "FAIL"
                print(
                    f"[{completed_count}/{total}] {status} "
                    f"latency={result.latency_ms}ms exit={result.exit_ip or '-'} "
                    f"iran={'YES' if result.iran_ok else 'NO'} "
                    f"reason={result.reason}",
                    flush=True,
                )

        print(f"Batch {batch_number}/{total_batches} completed", flush=True)

        if batch_number < total_batches and BATCH_PAUSE_SECONDS > 0:
            print(
                f"Resting {BATCH_PAUSE_SECONDS} seconds before the next batch...",
                flush=True,
            )
            time.sleep(BATCH_PAUSE_SECONDS)

    print("All batches completed", flush=True)

    healthy = sorted(
        (r for r in results if r.ok),
        key=lambda r: (r.latency_ms is None, r.latency_ms or 10**9),
    )
    failed = [r for r in results if not r.ok]
    iran_accessible = sorted(
        (r for r in healthy if r.iran_ok),
        key=lambda r: (r.latency_ms is None, r.latency_ms or 10**9),
    )

    (OUTPUT_DIR / "healthy.txt").write_text(
        "\n".join(r.config for r in healthy) + ("\n" if healthy else ""),
        encoding="utf-8",
    )
    (OUTPUT_DIR / "iran.txt").write_text(
        "\n".join(r.config for r in iran_accessible) + ("\n" if iran_accessible else ""),
        encoding="utf-8",
    )
    (OUTPUT_DIR / "failed.txt").write_text(
        "\n".join(r.config for r in failed) + ("\n" if failed else ""),
        encoding="utf-8",
    )
    (OUTPUT_DIR / "results.json").write_text(
        json.dumps(
            {
                "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "summary": {
                    "sources": len(read_urls()),
                    "source_errors": len(source_errors),
                    "tested": len(results),
                    "healthy": len(healthy),
                    "iran_accessible": len(iran_accessible),
                    "failed": len(failed),
                },
                "source_errors": source_errors,
                "results": [dataclasses.asdict(r) for r in sorted(results, key=lambda x: not x.ok)],
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    (OUTPUT_DIR / "summary.json").write_text(
        json.dumps(
            {
                "tested": len(results),
                "healthy": len(healthy),
                "iran_accessible": len(iran_accessible),
                "failed": len(failed),
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    print(f"Healthy: {len(healthy)} / {len(results)}", flush=True)
    print(f"Iran accessible: {len(iran_accessible)} / {len(healthy)} healthy configs", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
