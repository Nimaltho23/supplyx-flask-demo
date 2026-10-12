import difflib
import re
from typing import Any

# Enough coverage to catch typosquats without false-positive explosion
_TOP_PYPI = [
    "requests", "numpy", "pandas", "boto3", "botocore", "urllib3", "setuptools",
    "six", "python-dateutil", "pytz", "pyyaml", "certifi", "cryptography",
    "flask", "django", "fastapi", "sqlalchemy", "pydantic", "aiohttp", "click",
    "pillow", "scipy", "matplotlib", "pytest", "black", "typing-extensions",
]

_TOP_NPM = [
    "lodash", "express", "react", "axios", "moment", "chalk", "commander",
    "webpack", "typescript", "eslint", "jest", "vue", "next", "fastify",
    "underscore", "async", "bluebird", "dotenv", "uuid", "debug",
    "body-parser", "cors", "morgan", "helmet", "nodemon",
]


def _normalise(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


def _find_typosquat(name: str, registry: str) -> tuple[str | None, int | None]:
    targets = _TOP_PYPI if registry == "pypi" else _TOP_NPM
    norm = _normalise(name)
    best_target, best_dist = None, None
    for target in targets:
        if _normalise(target) == norm:
            continue
        ratio = difflib.SequenceMatcher(None, norm, _normalise(target)).ratio()
        if ratio >= 0.85:
            dist = max(len(norm), len(_normalise(target))) - int(
                ratio * max(len(norm), len(_normalise(target)))
            )
            if best_dist is None or dist < best_dist:
                best_target, best_dist = target, dist
    return best_target, best_dist


def _is_real_repo_url(url: str | None) -> bool:
    """Repo link must look like a real source-host URL (github/gitlab/bitbucket/sourcehut/codeberg).
    A bare homepage or a project landing page does NOT count."""
    if not url or len(url) < 10:
        return False
    url_l = url.lower()
    return any(host in url_l for host in (
        "github.com/", "gitlab.com/", "bitbucket.org/", "git.sr.ht/",
        "sourcehut.org/", "codeberg.org/", "git.launchpad.net/",
    ))


def extract_metadata_features(pkg_meta: dict) -> dict[str, Any]:
    name = pkg_meta.get("name", "")
    registry = pkg_meta.get("registry", "pypi")
    version = pkg_meta.get("version", "1.0.0")
    version_count = int(pkg_meta.get("version_count", 1) or 1)
    repository = pkg_meta.get("repository")
    homepage = pkg_meta.get("homepage")
    project_urls = pkg_meta.get("project_urls") or {}

    typosquat_target, typosquat_distance = _find_typosquat(name, registry)

    # Flag packages that claim a high major version with very few releases
    major = int((re.split(r"[.\-]", version)[0] or "0") if re.match(r"\d", version) else "0")
    version_jump_suspicious = major >= 5 and version_count <= 3

    # Repo link: any of repository / homepage / project_urls must point to a real source host
    candidate_urls = [repository, homepage, *(project_urls.values() if isinstance(project_urls, dict) else [])]
    has_repo_link = any(_is_real_repo_url(u) for u in candidate_urls)

    return {
        "account_age_days":        None,   # requires registry auth; filled in later
        "typosquat_target":        typosquat_target,
        "typosquat_distance":      typosquat_distance,
        "has_repo_link":           has_repo_link,
        "version_count":           version_count,
        "version_jump_suspicious": version_jump_suspicious,
    }
