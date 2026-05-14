"""Hand-Python baseline for ua_parse.capa. Idiomatic Python:
plain strings, native `in` operator for substring matching,
dataclasses for the result struct.
"""

from dataclasses import dataclass


BROWSER_CHROME = "chrome"
BROWSER_FIREFOX = "firefox"
BROWSER_SAFARI = "safari"
BROWSER_UNKNOWN = "unknown"

OS_LINUX = "linux"
OS_MAC = "mac"
OS_WINDOWS = "windows"
OS_OTHER = "other"


@dataclass
class UserAgent:
    browser: str
    os: str


def detect_browser(ua: str) -> str:
    if "Chrome" in ua:
        return BROWSER_CHROME
    if "Firefox" in ua:
        return BROWSER_FIREFOX
    if "Safari" in ua:
        return BROWSER_SAFARI
    return BROWSER_UNKNOWN


def detect_os(ua: str) -> str:
    if "Linux" in ua:
        return OS_LINUX
    if "Mac OS" in ua:
        return OS_MAC
    if "Windows" in ua:
        return OS_WINDOWS
    return OS_OTHER


def parse_user_agent(ua: str) -> UserAgent:
    return UserAgent(browser=detect_browser(ua), os=detect_os(ua))


def build_samples(n: int) -> list[str]:
    t0 = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"
    t1 = "Mozilla/5.0 (Macintosh; Intel Mac OS) Safari/17.0"
    t2 = "Mozilla/5.0 (Windows NT 10.0) Firefox/121.0"
    t3 = "Mozilla/5.0 (Linux; Android 13) Chrome/120.0"
    templates = [t0, t1, t2, t3]
    out: list[str] = []
    for i in range(n):
        out.append(templates[i % 4])
    return out


def parse_all(samples: list[str]) -> int:
    matched = 0
    for ua in samples:
        parsed = parse_user_agent(ua)
        if parsed.browser != BROWSER_UNKNOWN:
            matched += 1
    return matched


def workload() -> int:
    samples = build_samples(1000)
    return parse_all(samples)
