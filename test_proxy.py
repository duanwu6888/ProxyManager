import os
import time
import traceback
from urllib.parse import quote

import requests


IPIFY_URL = os.environ.get("PROXY_TEST_URL", "https://api.ipify.org?format=json")
PROXY_HOST = os.environ.get("PROXY_TEST_HOST", "")
PROXY_PORT = int(os.environ.get("PROXY_TEST_PORT", "0"))
PROXY_USER = os.environ.get("PROXY_TEST_USER", "")
PROXY_PASS = os.environ.get("PROXY_TEST_PASS", "")
TIMEOUT_SECONDS = int(os.environ.get("PROXY_TEST_TIMEOUT", "15"))
SCHEMES = tuple(
    scheme.strip()
    for scheme in os.environ.get("PROXY_TEST_SCHEMES", "socks5,socks5h").split(",")
    if scheme.strip()
)


def proxy_url(scheme: str) -> str:
    auth = ""
    if PROXY_USER or PROXY_PASS:
        auth = f"{quote(PROXY_USER, safe='')}:{quote(PROXY_PASS, safe='')}@"
    return f"{scheme}://{auth}{PROXY_HOST}:{PROXY_PORT}"


def test_scheme(scheme: str) -> bool:
    url = proxy_url(scheme)
    proxies = {"http": url, "https": url}

    started = time.perf_counter()
    exit_ip = ""
    success = False
    error = ""
    full_error = ""

    try:
        response = requests.get(
            IPIFY_URL,
            proxies=proxies,
            timeout=TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        exit_ip = data.get("ip", "")
        success = bool(exit_ip)
        if not exit_ip:
            error = "ipify response did not include ip"
    except requests.RequestException as exc:
        error = repr(exc)
        full_error = traceback.format_exc()
    except ValueError as exc:
        error = f"invalid JSON response: {exc!r}"
        full_error = traceback.format_exc()

    elapsed_ms = round((time.perf_counter() - started) * 1000)

    print("=" * 80)
    print(f"协议: {scheme}://")
    print(f"出口IP: {exit_ip or '-'}")
    print(f"是否成功: {'是' if success else '否'}")
    print(f"响应时间: {elapsed_ms} ms")
    if error:
        print(f"错误: {error}")
    if full_error:
        print("完整错误信息:")
        print(full_error.rstrip())
    return success


def main() -> None:
    if not PROXY_HOST or not PROXY_PORT:
        raise SystemExit(
            "Please set PROXY_TEST_HOST, PROXY_TEST_PORT, PROXY_TEST_USER, and PROXY_TEST_PASS."
        )

    results = [test_scheme(scheme) for scheme in SCHEMES]
    if not any(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
