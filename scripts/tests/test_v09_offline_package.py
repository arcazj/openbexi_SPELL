from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
import uuid
from pathlib import Path
from typing import Mapping, Sequence

import pytest


ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
PLAYWRIGHT_IMAGE = (
    "mcr.microsoft.com/playwright:v1.61.1-noble@"
    "sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48"
)
PLAYWRIGHT_IMAGE_ID = (
    "sha256:89924b46ec81c1c0eb0055a7d72790b8067a16a5d0d0512e8117a01aa4a5d7ee"
)
NODE_VERSION = "v24.17.0"
NPM_VERSION = "11.13.0"
PLAYWRIGHT_VERSION = "1.61.1"
CHROMIUM_VERSION = "149.0.7827.55"
CHROMIUM_REVISION = "chromium-1228"
CHROMIUM_PATH = "/ms-playwright/chromium-1228/chrome-linux64/chrome"
CHROMIUM_SHA256 = "2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801"
QUALIFICATION_RELEASE = "v0.9.0"
MAX_FRONTEND_SOURCE_FILES = 2_000
MAX_FRONTEND_SOURCE_BYTES = 32 * 1024 * 1024
MAX_FRONTEND_ARCHIVE_BYTES = 64 * 1024 * 1024


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    assert files, f"tree is empty: {root}"
    for path in files:
        assert not path.is_symlink(), f"tree contains a symbolic link: {path}"
        relative = path.relative_to(root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(arguments),
        cwd=cwd,
        env=None if env is None else dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    assert completed.returncode == 0, (
        f"command failed ({completed.returncode}): {arguments[0]}\n"
        f"stdout:\n{completed.stdout[-4000:]}\n"
        f"stderr:\n{completed.stderr[-4000:]}"
    )
    return completed


def _run_with_input(
    arguments: Sequence[str], payload: bytes, *, timeout: int = 300
) -> None:
    completed = subprocess.run(
        list(arguments),
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    assert completed.returncode == 0, (
        f"command failed ({completed.returncode}): {arguments[0]}\n"
        f"stdout:\n{completed.stdout[-4000:].decode('utf-8', errors='replace')}\n"
        f"stderr:\n{completed.stderr[-4000:].decode('utf-8', errors='replace')}"
    )


def _frontend_source_archive(root: Path) -> bytes:
    entries = sorted(root.rglob("*"), key=lambda path: path.as_posix())
    assert entries and len(entries) <= MAX_FRONTEND_SOURCE_FILES
    total_bytes = 0
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path in entries:
            assert not path.is_symlink(), f"frontend source contains a link: {path}"
            relative = path.relative_to(root).as_posix()
            info = tarfile.TarInfo(relative + ("/" if path.is_dir() else ""))
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            if path.is_dir():
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
                continue
            assert path.is_file(), f"frontend source entry is not regular: {path}"
            file_size = path.stat().st_size
            assert 0 <= file_size <= MAX_FRONTEND_SOURCE_BYTES - total_bytes
            payload = path.read_bytes()
            assert len(payload) == file_size
            total_bytes += len(payload)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
    value = buffer.getvalue()
    assert 0 < len(value) <= MAX_FRONTEND_ARCHIVE_BYTES
    return value


def _required_path(name: str, *, directory: bool = False) -> Path:
    raw = os.environ.get(name)
    assert raw, f"canonical offline qualification did not set {name}"
    path = Path(raw).resolve(strict=True)
    assert path.is_dir() if directory else path.is_file(), f"{name} has the wrong type"
    assert not path.is_symlink(), f"{name} is a symbolic link"
    return path


def _wait_for_probe(
    docker: Path, container: str, code: str, *, timeout: float = 60.0
) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        completed = subprocess.run(
            [str(docker), "exec", container, "python", "-I", "-c", code],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if completed.returncode == 0 and completed.stdout.strip() == "READY":
            return
        last = (completed.stdout + completed.stderr)[-2000:]
        time.sleep(0.25)
    raise AssertionError(f"offline health probe did not become ready: {last}")


def _assert_network_none(docker: Path, container: str) -> None:
    observed = _run(
        [
            str(docker),
            "inspect",
            "--format",
            "{{.HostConfig.NetworkMode}}",
            container,
        ]
    ).stdout.strip()
    assert observed == "none"


def _remove_container(docker: Path, container: str) -> None:
    subprocess.run(
        [str(docker), "rm", "-f", container],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def test_v09_offline_package_dependency_closure_is_exactly_pinned() -> None:
    lock = json.loads((FRONTEND / "package-lock.json").read_text(encoding="utf-8"))
    assert lock["lockfileVersion"] == 3
    assert lock["packages"][""]["version"] == "0.9.0"
    packages = {name: value for name, value in lock["packages"].items() if name}
    assert packages
    assert all(
        isinstance(value.get("resolved"), str)
        and value["resolved"].startswith("https://registry.npmjs.org/")
        and isinstance(value.get("integrity"), str)
        and value["integrity"].startswith("sha512-")
        and not value.get("link", False)
        for value in packages.values()
    )

    for relative in (
        "backend/requirements.hashes.lock",
        "driver_host/pki-requirements.hashes.lock",
        "contracts/generator-requirements.hashes.lock",
        "scripts/supply-chain-requirements.hashes.lock",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        requirement_lines = [
            line
            for line in source.splitlines()
            if line and not line[0].isspace() and not line.startswith("#")
        ]
        assert requirement_lines
        assert all("==" in line and line.endswith(" \\") for line in requirement_lines)
        assert source.count("--hash=sha256:") >= len(requirement_lines)


def test_v09_offline_package_build_install_and_network_none_health(
    tmp_path: Path,
) -> None:
    if os.environ.get("SPELL_V09_OFFLINE_PROOF") != "1":
        pytest.skip("executed only by the canonical v0.9 candidate and Final runners")

    source_root = _required_path("SPELL_V09_OFFLINE_SOURCE_ROOT", directory=True)
    docker = _required_path("SPELL_V09_OFFLINE_DOCKER_EXE")
    npm_cache_volume = os.environ.get("SPELL_V09_OFFLINE_NPM_CACHE_VOLUME", "")
    assert re.fullmatch(r"sv09-offline-cache-[0-9a-f]{12}", npm_cache_volume)
    image = os.environ.get("SPELL_V09_OFFLINE_QUALIFICATION_IMAGE", "")
    assert image.startswith("sha256:") and len(image) == 71

    frontend = source_root / "frontend"
    assert frontend.is_dir() and not frontend.is_symlink()
    inspected_id = _run(
        [str(docker), "image", "inspect", image, "--format", "{{.Id}}"]
    ).stdout.strip()
    assert inspected_id == image
    playwright_image_id = _run(
        [
            str(docker),
            "image",
            "inspect",
            PLAYWRIGHT_IMAGE,
            "--format",
            "{{.Id}}",
        ]
    ).stdout.strip()
    assert playwright_image_id == PLAYWRIGHT_IMAGE_ID
    assert (
        _run(
            [str(docker), "volume", "inspect", npm_cache_volume, "--format", "{{.Name}}"]
        ).stdout.strip()
        == npm_cache_volume
    )
    assert (
        _run(
            [str(docker), "run", "--rm", "--network", "none", PLAYWRIGHT_IMAGE, "node", "--version"]
        ).stdout.strip()
        == NODE_VERSION
    )
    assert (
        _run(
            [str(docker), "run", "--rm", "--network", "none", PLAYWRIGHT_IMAGE, "npm", "--version"]
        ).stdout.strip()
        == NPM_VERSION
    )

    locked_probe = (
        "import importlib.metadata,json,os;"
        "expected={'fastapi':'0.139.2','pytest':'9.1.1','sqlalchemy':'2.0.51','uvicorn':'0.51.0'};"
        "actual={name:importlib.metadata.version(name) for name in expected};"
        "assert actual==expected,(actual,expected);"
        "assert os.environ['SPELL_QUALIFICATION_RELEASE']=='v0.9.0';"
        "print(json.dumps(actual,sort_keys=True,separators=(',',':')))"
    )
    _run(
        [
            str(docker),
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--entrypoint",
            "python",
            image,
            "-I",
            "-c",
            locked_probe,
        ]
    )

    offline_frontend = tmp_path / "frontend"
    shutil.copytree(
        frontend,
        offline_frontend,
        symlinks=True,
        ignore=shutil.ignore_patterns(
            "node_modules", "dist", "coverage", "playwright-report", "test-results"
        ),
    )
    assert not any(path.is_symlink() for path in offline_frontend.rglob("*"))

    browser_probe = """
const crypto = require('node:crypto');
const fs = require('node:fs');
const { chromium } = require('playwright');
(async () => {
  const executable = chromium.executablePath();
  const browser = await chromium.launch({ headless: true });
  const result = {
    executable,
    sha256: crypto.createHash('sha256').update(fs.readFileSync(executable)).digest('hex'),
    version: browser.version(),
    playwright: require('@playwright/test/package.json').version,
  };
  await browser.close();
  process.stdout.write(JSON.stringify(result));
})().catch((error) => { console.error(error); process.exit(1); });
"""
    tree_probe = """
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const root = '/work/dist';
function files(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    return entry.isDirectory() ? files(target) : [target];
  });
}
const digest = crypto.createHash('sha256');
for (const target of files(root).sort()) {
  const relative = path.relative(root, target).split(path.sep).join('/');
  const name = Buffer.from(relative, 'utf8');
  const payload = fs.readFileSync(target);
  const nameLength = Buffer.alloc(8);
  const payloadLength = Buffer.alloc(8);
  nameLength.writeBigUInt64BE(BigInt(name.length));
  payloadLength.writeBigUInt64BE(BigInt(payload.length));
  digest.update(nameLength).update(name).update(payloadLength).update(payload);
}
process.stdout.write(digest.digest('hex'));
"""
    suffix = uuid.uuid4().hex[:12]
    workspace_volume = f"sv09-offline-work-{suffix}"
    copy_container = f"spell-v09-offline-copy-{suffix}"
    web_container = f"spell-v09-offline-web-{suffix}"
    api_container = f"spell-v09-offline-api-{suffix}"
    static_server = (
        "from functools import partial;"
        "from http.server import SimpleHTTPRequestHandler,ThreadingHTTPServer;"
        "handler=partial(SimpleHTTPRequestHandler,directory='/work/dist');"
        "ThreadingHTTPServer(('127.0.0.1',8080),handler).serve_forever()"
    )
    static_probe = (
        "import urllib.request;"
        "r=urllib.request.urlopen('http://127.0.0.1:8080/development.html',timeout=2);"
        "b=r.read();"
        "assert r.status==200 and b'development' in b.lower();"
        "print('READY')"
    )
    api_server = (
        "import pathlib,sys;"
        "pathlib.Path('/tmp/spell-data').mkdir();"
        "pathlib.Path('/tmp/spell-backups').mkdir();"
        "sys.path.insert(0,'/qualification-source');"
        "import uvicorn;"
        "uvicorn.run('backend.app:app',host='127.0.0.1',port=8000,log_level='warning')"
    )
    api_probe = (
        "import json,urllib.request;"
        "q=urllib.request.Request('http://127.0.0.1:8000/api/v1/health',headers={'Host':'127.0.0.1'});"
        "r=urllib.request.urlopen(q,timeout=2);d=json.load(r);"
        "assert r.status==200 and d['status']=='ok' and d['version']=='0.9.0';"
        "print('READY')"
    )
    try:
        _run(
            [
                str(docker),
                "volume",
                "create",
                "--label",
                "org.openbexi.spell.v09.offline-proof=1",
                workspace_volume,
            ]
        )
        _run_with_input(
            [
                str(docker),
                "run",
                "--rm",
                "-i",
                "--name",
                copy_container,
                "--label",
                "org.openbexi.spell.v09.offline-proof=1",
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:size=64m,noexec,nosuid",
                "--mount",
                f"type=volume,source={workspace_volume},target=/work",
                PLAYWRIGHT_IMAGE,
                "tar",
                "-xf",
                "-",
                "-C",
                "/work",
                "--no-same-owner",
                "--no-same-permissions",
            ],
            _frontend_source_archive(offline_frontend),
        )
        container_base = [
            str(docker),
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:size=1g,noexec,nosuid",
            "--mount",
            f"type=volume,source={workspace_volume},target=/work",
            "--mount",
            f"type=volume,source={npm_cache_volume},target=/npm-cache",
            "--workdir",
            "/work",
            "-e",
            "CI=1",
            "-e",
            "HOME=/tmp/home",
            "-e",
            "NPM_CONFIG_CACHE=/npm-cache",
            "-e",
            "NPM_CONFIG_OFFLINE=true",
            "-e",
            "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright",
            "-e",
            "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1",
            PLAYWRIGHT_IMAGE,
        ]
        _run([*container_base, "npm", "cache", "verify", "--cache", "/npm-cache"])
        _run(
            [
                *container_base,
                "npm",
                "ci",
                "--offline",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--cache",
                "/npm-cache",
            ]
        )
        _run([*container_base, "npm", "run", "build"])
        browser = json.loads(
            _run([*container_base, "node", "-e", browser_probe]).stdout
        )
        assert browser == {
            "executable": CHROMIUM_PATH,
            "sha256": CHROMIUM_SHA256,
            "version": CHROMIUM_VERSION,
            "playwright": PLAYWRIGHT_VERSION,
        }
        offline_tree_digest = _run(
            [*container_base, "node", "-e", tree_probe]
        ).stdout.strip()
        assert offline_tree_digest == _tree_digest(frontend / "dist")

        _run(
            [
                str(docker),
                "run",
                "-d",
                "--name",
                web_container,
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:size=32m,noexec,nosuid",
                "--mount",
                f"type=volume,source={workspace_volume},target=/work,readonly",
                "--entrypoint",
                "python",
                image,
                "-I",
                "-c",
                static_server,
            ]
        )
        _assert_network_none(docker, web_container)
        _wait_for_probe(docker, web_container, static_probe)

        _run(
            [
                str(docker),
                "run",
                "-d",
                "--name",
                api_container,
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:size=256m,noexec,nosuid",
                "-e",
                "DATABASE_URL=sqlite:////tmp/spell-v09-offline.db",
                "-e",
                "SPELL_DATA_DIR=/tmp/spell-data",
                "-e",
                "SPELL_V0007_BACKUP_DIR=/tmp/spell-backups",
                "-e",
                "SPELL_JWT_HS256_SECRET=offline-proof-only-0123456789abcdef0123456789abcdef",
                "-e",
                "SPELL_DRIVER_ENABLED=false",
                "--entrypoint",
                "python",
                image,
                "-I",
                "-c",
                api_server,
            ]
        )
        _assert_network_none(docker, api_container)
        _wait_for_probe(docker, api_container, api_probe, timeout=90.0)
    finally:
        _remove_container(docker, copy_container)
        _remove_container(docker, api_container)
        _remove_container(docker, web_container)
        subprocess.run(
            [str(docker), "volume", "rm", "-f", workspace_volume],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
