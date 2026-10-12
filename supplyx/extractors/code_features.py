"""
Code-feature extractor — tightened against legitimate-code false-positives.

Lessons learned from the v1 dataset audit (May 2026):
- has_exec_eval triggered on jinja2 / sympy / ipython etc. → now requires
  co-occurrence with decode / fetch / install-script context.
- has_credential_access triggered on boto3 / kubernetes-client → now restricted
  to install scripts OR within 200 chars of file-write/exfil patterns.
- has_network_in_install matched home_page URLs in setup.py → URLs in
  metadata-assignment positions are excluded.
- has_os_targeting matched any literal 'win32' string → now requires a
  conditional gate (`if platform == ...`).
- dangerous_import_count was triggered by ordinary HTTP libs → now only counts
  "rare" dangerous imports (ctypes, marshal, pickle, importlib) plus subprocess.
- api_category_count rewarded ordinary library code → categories tightened.
"""
import math
import os
import re
from collections import Counter
from typing import Any

# Imports that are RARE in benign code and common in payload-style malicious code.
# Note: subprocess/pickle/importlib are legitimately used by many benign packages
# (build tools, dynamic loaders) so they are NOT counted here. We count only
# imports that have essentially no legitimate use in a typical pure-Python package.
DANGEROUS_IMPORTS = {
    "ctypes",   # rarely needed in pure-Python packages, common in Win32 stealers
    "cffi",     # ditto
    "marshal",  # bytecode (un)marshalling — rarely legit at package level
}

# Imports that need to appear in INSTALL SCRIPTS specifically to count
# (legit packages may import these in their library code, but rarely in setup.py).
_INSTALL_TIME_DANGEROUS_IMPORTS = {
    "subprocess", "socket", "urllib", "urllib2", "urllib3",
    "requests", "http.client", "ftplib", "pickle",
}

# Credential-access patterns: filesystem paths and known token env vars.
_CRED_PATH_PATTERNS = [
    re.compile(r"\.ssh[/\\](id_rsa|id_ed25519|authorized_keys)"),
    re.compile(r"\.aws[/\\](credentials|config)"),
    re.compile(r"\.npmrc"),
    re.compile(r"\.netrc"),
    re.compile(r"\.docker[/\\]config\.json"),
    re.compile(r"\.gitconfig"),
    re.compile(r"AppData[/\\].*\\Login Data"),
    re.compile(r"Local\\Google\\Chrome\\User Data"),
]

# Network primitives we don't trust in install scripts. Function-call syntax
# required so that bare domain names (e.g. "requests.readthedocs.io" in a URL field)
# don't trigger.
_NETWORK_PATTERNS = [
    re.compile(r'\brequests\.(?:get|post|put|delete|patch|head|request|Session)\s*\('),
    re.compile(r'\b(?:urllib|urllib2|urllib3|http\.client|httplib|aiohttp|httpx)\.[\w_]+\s*\('),
    re.compile(r'\b(?:urlopen|urlretrieve)\s*\('),
    re.compile(r'\bsocket\.(?:socket|connect|create_connection)\s*\('),
    # Shell-style downloads inside install scripts (string literals OK)
    re.compile(r'\bcurl\s+(?:-[A-Za-z]*\s+)*https?://'),
    re.compile(r'\bwget\s+(?:-[A-Za-z]*\s+)*https?://'),
]

# eval/exec are too generic. Trigger only when paired with decode/download.
_EXEC_NEAR_DECODE = re.compile(
    r'(?:'
    r'(?:eval|exec|compile|__import__)\s*\([^)]{0,400}'
    r'(?:base64\.b64decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|'
    r'urlopen|urlretrieve|requests\.get|urllib\.request)'
    r')|(?:'
    r'(?:base64\.b64decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|'
    r'urlopen|urlretrieve|requests\.get|urllib\.request)'
    r'[^)]{0,400}'
    r'(?:eval|exec|compile|__import__)\s*\('
    r')',
    re.S,
)

# Obfuscation: large opaque blobs or chained decode calls.
_OBFUSCATION_PATTERNS = [
    re.compile(r'base64\.b64decode\s*\(\s*[\'"][A-Za-z0-9+/]{40,}={0,2}[\'"]'),
    re.compile(r'codecs\.decode\s*\([^)]*[\'"](rot13|hex|zlib|base64)[\'"]'),
    # Long base64-ish run of chars, anywhere (not just in solo-quoted strings).
    # PowerShell -EncodedCommand and Python exec(base64...) both look like this.
    re.compile(r'[A-Za-z0-9+/]{200,}={0,2}'),
    # Long hex/unicode escape runs
    re.compile(r'(\\x[0-9a-fA-F]{2}){30,}'),
    re.compile(r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){10,}"),
    # Encoded shell payloads (windows powershell / unix bash -c base64)
    re.compile(r'-EncodedCommand\s+[A-Za-z0-9+/]{50,}={0,2}', re.I),
    re.compile(r'(?:bash|sh)\s+-c\s+["\']?\$\(echo\s+[A-Za-z0-9+/]{40,}={0,2}\s*\|\s*base64'),
]

# OS targeting: require a platform check AND a suspicious payload nearby
# (subprocess/curl/wget/eval/exec/PowerShell). Pure cross-platform code is NOT a malicious signal.
_OS_GATED_PATTERNS = [
    re.compile(
        r'(?:'
        r'(?:if\s+(?:sys\.platform|platform\.system\s*\(\s*\)|os\.name)\s*[=!]=\s*[\'"](?:win32|linux|darwin|Windows|Linux|Darwin|nt|posix)[\'"])'
        r'[^\n]{0,400}'
        r'(?:subprocess|os\.system|os\.popen|powershell|curl\s+http|wget\s+http|exec|eval|__import__)'
        r')|(?:'
        r'(?:subprocess|os\.system|os\.popen|powershell|curl\s+http|wget\s+http|exec|eval|__import__)'
        r'[^\n]{0,400}'
        r'(?:if\s+(?:sys\.platform|platform\.system\s*\(\s*\)|os\.name)\s*[=!]=\s*[\'"](?:win32|linux|darwin|Windows|Linux|Darwin|nt|posix)[\'"])'
        r')',
        re.S,
    ),
]

# External payload: download THEN execute, on a SINGLE statement (no newlines between).
# Imports of urlopen at the top of a file + unrelated subprocess use later don't count.
_EXTERNAL_PAYLOAD_PATTERNS = [
    # download → exec, single-line/single-statement only
    re.compile(
        r'(?:urlretrieve|urlopen|requests\.get|requests\.post|urllib\.request\.urlopen|fetch|axios)'
        r'[^\n]{0,200}'
        r'(?:exec|eval|compile|__import__|subprocess\.\w+|os\.system|os\.popen)\s*\('
    ),
    # exec wrapping a download call
    re.compile(
        r'(?:exec|eval|compile|__import__)\s*\([^)\n]{0,200}'
        r'(?:urlopen|urlretrieve|requests\.get|urllib\.request|fetch\s*\(|axios)'
    ),
    # shell: subprocess running curl/wget piped to sh
    re.compile(r'subprocess\.(?:check_output|run|Popen)\s*\([^)\n]{0,300}(?:curl|wget)\s+(?:-[A-Za-z]*\s+)?https?://'),
    # bash: piped curl|sh
    re.compile(r'curl\s+(?:-[A-Za-z]*\s+)*https?://\S+\s*\|\s*(?:sh|bash|python)'),
]

# API categories — only triggers on SUSPICIOUS combinations.
_API_CATEGORIES: dict[str, list[re.Pattern]] = {
    "process_spawn":     [re.compile(r'\b(subprocess\.(check_output|Popen|run|call)|os\.(system|popen|execv|execl)|child_process\.exec)\b')],
    "shell_command":     [re.compile(r'(?:os\.system|subprocess\.\w+|child_process)\s*\([^)]*(?:curl|wget|nc\s+-|/bin/sh|/bin/bash|cmd\.exe|powershell)', re.I)],
    "dynamic_execution": [re.compile(r'(?:eval|exec|compile|__import__)\s*\([^)]{0,200}(?:base64|codecs|decode|fromhex|zlib)')],
    "exfiltration":      [re.compile(r'(?:requests|urllib|http\.client|httpx|aiohttp|axios|fetch)\s*\.\s*(?:post|put|patch)\s*\([^)]{0,200}(?:host|user|env|token|key|aws|password)', re.I)],
    "fs_persistence":    [re.compile(r'(?:os\.chmod|os\.chown|shutil\.copy[a-z]*)\s*\([^)]*(?:/etc/|/usr/|\.bashrc|\.profile|\.zshrc|Startup|autorun)', re.I)],
}

# URL-in-metadata-field assignments (to be excluded from network detection).
_METADATA_URL_FIELDS = re.compile(
    r"(?:home_page|homepage|url|download_url|project_urls|repository|documentation)\s*[=:]"
    r"\s*[\[\{]?\s*[\'\"]https?://",
    re.I,
)

_INSTALL_FILENAMES = {"setup.py", "setup.cfg", "package.json", "pyproject.toml", "MANIFEST.in"}
_SOURCE_EXTENSIONS = (".py", ".js", ".ts", ".mjs", ".cjs", ".sh")
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".tox", "dist", "build",
              "test", "tests", "docs", "examples", "example", "samples",
              ".github", ".vscode", ".idea"}


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _read_sources(package_dir: str, max_files: int = 200) -> list[tuple[str, str]]:
    """Walk the package, skipping test/doc/example dirs that pollute features."""
    results = []
    count = 0
    for root, dirs, files in os.walk(package_dir):
        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS]
        for fname in files:
            if count >= max_files:
                return results
            if fname.endswith(_SOURCE_EXTENSIONS):
                path = os.path.join(root, fname)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        results.append((path, fh.read()))
                    count += 1
                except OSError:
                    pass
    return results


def _read_install_scripts(package_dir: str) -> str:
    """Only the install-time entry points. These should be tiny in benign packages."""
    content = ""
    for fname in _INSTALL_FILENAMES:
        path = os.path.join(package_dir, fname)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content += fh.read() + "\n"
            except OSError:
                pass
    return content


def _strip_metadata_urls(text: str) -> str:
    """Remove URLs assigned to metadata fields so they don't trigger network heuristics."""
    return _METADATA_URL_FIELDS.sub("__METADATA_URL__:\"", text)


def _has_credential_access(install_src: str, all_src: str) -> bool:
    """Credential access is suspicious if:
       (a) referenced anywhere in install scripts, OR
       (b) referenced AND co-located with file-write / network primitives in source."""
    if any(p.search(install_src) for p in _CRED_PATH_PATTERNS):
        return True
    for cred_p in _CRED_PATH_PATTERNS:
        for m in cred_p.finditer(all_src):
            window = all_src[max(0, m.start() - 400) : m.end() + 400]
            if re.search(r'\b(requests\.(post|put)|urlopen|socket\.|open\s*\([^)]+,\s*[\'\"]w)', window):
                return True
    return False


def _install_lines(install_src: str) -> int:
    """Non-blank, non-comment lines in install scripts."""
    lines = [ln for ln in install_src.splitlines()
             if ln.strip() and not ln.strip().startswith(("#", "//"))]
    return len(lines)


def extract_code_features(package_dir: str) -> dict[str, Any]:
    sources = _read_sources(package_dir)
    install_src_raw = _read_install_scripts(package_dir)
    install_src = _strip_metadata_urls(install_src_raw)
    all_src = "\n".join(src for _, src in sources)
    all_src_clean = _strip_metadata_urls(all_src)

    # Entropy: max over a bounded number of 200-char windows per file
    max_entropy = 0.0
    for _, src in sources:
        if not src:
            continue
        n_windows = min(20, max(1, len(src) // 200))
        for i in range(0, n_windows * 200, 200):
            window = src[i : i + 200]
            if len(window) < 50:
                break
            e = _shannon_entropy(window)
            if e > max_entropy:
                max_entropy = e

    has_network_in_install = any(p.search(install_src) for p in _NETWORK_PATTERNS)
    has_exec_eval = bool(_EXEC_NEAR_DECODE.search(all_src_clean) or _EXEC_NEAR_DECODE.search(install_src))
    has_credential_access = _has_credential_access(install_src, all_src_clean)
    has_obfuscated_code = any(p.search(all_src_clean) for p in _OBFUSCATION_PATTERNS)
    has_os_targeting = any(p.search(all_src_clean) for p in _OS_GATED_PATTERNS)
    has_external_payload = any(p.search(all_src_clean) for p in _EXTERNAL_PAYLOAD_PATTERNS)

    dangerous_import_count = sum(
        1 for imp in DANGEROUS_IMPORTS
        if re.search(rf"\b(?:import|from)\s+{re.escape(imp)}\b", all_src_clean)
    )
    # Plus: count network/process imports IF they appear in install scripts
    # (legitimate packages rarely need urllib/subprocess at install time).
    dangerous_import_count += sum(
        1 for imp in _INSTALL_TIME_DANGEROUS_IMPORTS
        if re.search(rf"\b(?:import|from)\s+{re.escape(imp)}\b", install_src)
    )

    api_category_count = sum(
        1 for patterns in _API_CATEGORIES.values()
        if any(p.search(all_src_clean) for p in patterns)
    )

    return {
        "entropy_max":              round(max_entropy, 4),
        "has_network_in_install":   has_network_in_install,
        "has_credential_access":    has_credential_access,
        "has_obfuscated_code":      has_obfuscated_code,
        "has_exec_eval":            has_exec_eval,
        "install_script_lines":     _install_lines(install_src_raw),
        "dangerous_import_count":   dangerous_import_count,
        "has_os_targeting":         has_os_targeting,
        "has_external_payload":     has_external_payload,
        "api_category_count":       api_category_count,
    }
