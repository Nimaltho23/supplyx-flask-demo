"""
Supplyx dependency gate.

Scores every dependency in the given requirements files with the Supplyx
malicious-package model and exits non-zero if any is high risk. Archives are
downloaded and unpacked, never installed, so no package code runs.

    python -m supplyx.scan requirements.txt [more.txt ...] [--threshold 0.6]
"""
import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

import numpy as np
import requests
import xgboost as xgb

from supplyx.archive import UnsafeArchiveError, safe_unpack
from supplyx.extractors.code_features import extract_code_features
from supplyx.extractors.metadata_features import extract_metadata_features

MODEL_FILE = Path(__file__).parent / "model" / "champion.json"
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".zip", ".whl")

FEATURES = [
    "entropy_max", "has_network_in_install", "has_credential_access",
    "has_obfuscated_code", "has_exec_eval", "install_script_lines",
    "dangerous_import_count", "has_os_targeting", "has_external_payload",
    "api_category_count", "typosquat_distance", "is_typosquat",
    "version_jump_suspicious",
]

LABELS = {
    "entropy_max":             "high-entropy strings",
    "has_network_in_install":  "network call in install script",
    "has_credential_access":   "credential file access",
    "has_obfuscated_code":     "obfuscated or encoded code",
    "has_exec_eval":           "exec/eval on decoded or downloaded data",
    "install_script_lines":    "install script length",
    "dangerous_import_count":  "dangerous imports",
    "has_os_targeting":        "OS-specific payload gating",
    "has_external_payload":    "downloads then executes a payload",
    "api_category_count":      "suspicious API combinations",
    "typosquat_distance":      "name distance to a popular package",
    "is_typosquat":            "typosquats a popular package",
    "version_jump_suspicious": "suspicious version jump",
}

_session = requests.Session()
_session.headers["User-Agent"] = "supplyx-ci-gate/1.0"


def risk_level(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.3:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Requirements parsing
# ---------------------------------------------------------------------------

def parse_requirements(path: Path, seen: set[Path] | None = None) -> list[dict]:
    """Return [{'kind': 'pypi'|'local', ...}] for one requirements file, following -r."""
    seen = seen if seen is not None else set()
    path = path.resolve()
    if path in seen:
        return []
    seen.add(path)

    deps = []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")):
            deps += parse_requirements(path.parent / line.split(None, 1)[1], seen)
        elif line.startswith("-"):
            continue  # other pip options
        elif line.endswith(ARCHIVE_SUFFIXES):
            deps.append({"kind": "local", "path": (path.parent / line).resolve(), "source": path.name})
        else:
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[.*?\])?\s*(?:==\s*([^\s;]+))?", line)
            if m:
                deps.append({"kind": "pypi", "name": m.group(1), "version": m.group(2), "source": path.name})
    return deps


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def fetch_pypi(name: str, version: str | None) -> tuple[bytes, dict]:
    """Download the sdist (or a wheel) straight from PyPI. Nothing is installed."""
    project = _session.get(f"https://pypi.org/pypi/{name}/json", timeout=30)
    project.raise_for_status()
    pdata = project.json()
    version = version or pdata["info"]["version"]

    release = _session.get(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30)
    release.raise_for_status()
    rdata = release.json()
    files = rdata["urls"]
    chosen = next((f for f in files if f["packagetype"] == "sdist"), files[0] if files else None)
    if chosen is None:
        raise RuntimeError("no downloadable files for this release")
    if chosen["size"] > MAX_ARCHIVE_BYTES:
        raise RuntimeError("archive exceeds the 50 MB cap")

    blob = _session.get(chosen["url"], timeout=120)
    blob.raise_for_status()
    info = rdata["info"]
    meta = {
        "name": info["name"],
        "version": version,
        "registry": "pypi",
        "homepage": info.get("home_page"),
        "repository": (info.get("project_urls") or {}).get("Source"),
        "project_urls": info.get("project_urls"),
        "version_count": len(pdata.get("releases", {})),
    }
    return blob.content, meta


def read_local(path: Path) -> tuple[bytes, dict]:
    stem = path.name
    for suffix in ARCHIVE_SUFFIXES:
        stem = stem.removesuffix(suffix)
    name, _, version = stem.rpartition("-")
    meta = {"name": name or stem, "version": version or "0", "registry": "pypi", "version_count": 1}
    return path.read_bytes(), meta


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _package_root(tmpdir: str) -> str:
    subdirs = [os.path.join(tmpdir, e) for e in os.listdir(tmpdir)
               if os.path.isdir(os.path.join(tmpdir, e))]
    return subdirs[0] if len(subdirs) == 1 else tmpdir


def extract_features(archive: bytes, meta: dict) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        safe_unpack(archive, tmpdir)
        code = extract_code_features(_package_root(tmpdir))
    md = extract_metadata_features(meta)
    row = {**code, **md}
    row["is_typosquat"] = md["typosquat_target"] is not None
    row["typosquat_distance"] = md["typosquat_distance"] or 0
    return {f: float(row[f]) for f in FEATURES} | {"typosquat_target": md["typosquat_target"]}


def score(model: xgb.Booster, feats: dict) -> tuple[float, list[tuple[str, float]]]:
    dm = xgb.DMatrix(np.array([[feats[f] for f in FEATURES]]), feature_names=FEATURES)
    prob = float(model.predict(dm)[0])
    # pred_contribs is XGBoost's built-in TreeSHAP; the last column is the bias term
    contribs = model.predict(dm, pred_contribs=True)[0][:-1]
    top = sorted(zip(FEATURES, contribs.tolist()), key=lambda x: x[1], reverse=True)
    return prob, [(f, v) for f, v in top if v >= 0.05][:4]


def scan(files: list[Path], threshold: float) -> int:
    model = xgb.Booster()
    model.load_model(str(MODEL_FILE))

    deps: list[dict] = []
    seen: set[Path] = set()
    for f in files:
        deps += parse_requirements(f, seen)

    results = []
    for dep in deps:
        label = dep["path"].name if dep["kind"] == "local" else f'{dep["name"]}=={dep["version"] or "latest"}'
        try:
            archive, meta = read_local(dep["path"]) if dep["kind"] == "local" else fetch_pypi(dep["name"], dep["version"])
            feats = extract_features(archive, meta)
            prob, reasons = score(model, feats)
            results.append({"label": f'{meta["name"]}=={meta["version"]}', "source": dep["source"],
                            "score": prob, "risk": risk_level(prob), "reasons": reasons,
                            "typosquat_target": feats["typosquat_target"], "error": None})
        except (requests.RequestException, RuntimeError, UnsafeArchiveError, OSError) as exc:
            # fail closed: a dependency we cannot inspect does not pass the gate
            results.append({"label": label, "source": dep["source"], "score": None, "risk": "error",
                            "reasons": [], "typosquat_target": None, "error": str(exc)})

    blocked = [r for r in results if r["error"] or r["score"] >= threshold]
    report(results, blocked, threshold)
    return 1 if blocked else 0


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _why(r: dict) -> str:
    if r["error"]:
        return f"could not inspect: {r['error']}"
    parts = [f"{LABELS[f]} (+{v:.2f})" for f, v in r["reasons"]]
    if r["typosquat_target"]:
        parts.insert(0, f"looks like '{r['typosquat_target']}'")
    return "; ".join(parts) or "no strong signals"


def report(results: list[dict], blocked: list[dict], threshold: float) -> None:
    print(f"Supplyx dependency gate — {len(results)} dependencies, block at score >= {threshold}\n")
    for r in results:
        score_txt = "  n/a" if r["score"] is None else f"{r['score']:.3f}"
        flag = "BLOCK" if r in blocked else "ok   "
        print(f"  {flag}  {score_txt}  {r['risk']:<8}  {r['label']}")
        if r in blocked:
            print(f"         why: {_why(r)}")
    print()
    print(f"FAILED: {len(blocked)} dependency(ies) blocked." if blocked else "PASSED: no high-risk dependencies.")

    for r in blocked:  # GitHub annotation on the pull request / commit
        print(f"::error file={r['source']},title=Supplyx blocked {r['label']}::"
              f"risk {r['risk']}. {_why(r)}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        lines = ["## Supplyx dependency gate", "",
                 "| dependency | score | risk | verdict | top signals |", "|---|---|---|---|---|"]
        for r in results:
            score_txt = "n/a" if r["score"] is None else f"{r['score']:.3f}"
            verdict = "**BLOCKED**" if r in blocked else "pass"
            lines.append(f"| `{r['label']}` | {score_txt} | {r['risk']} | {verdict} | {_why(r)} |")
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("requirements", nargs="+", type=Path)
    ap.add_argument("--threshold", type=float, default=0.6, help="block at this score or above (default 0.6 = high)")
    args = ap.parse_args()
    sys.exit(scan(args.requirements, args.threshold))


if __name__ == "__main__":
    main()
