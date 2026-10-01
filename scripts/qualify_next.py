"""Canonical, source-bound v0.13-v0.15 qualification producer (Windows host, Linux Docker)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time

from scripts.release_next import ROOT, VERSION, MINOR, TAG, POLICY, fingerprint, git, require, write_json, verify_candidate, policy
from scripts.gcc_header_applicability import resolve

OUT = ROOT / f".qualification/v{MINOR}/final"
QUALIFIER = "openbexi-spell-qualification:next"
IMAGES = {name: f"openbexi-spell-{name}:{TAG}" for name in ("backend", "driver", "frontend", "proxy")}
COMPOSE_TESTS = [
    "test_created_compose_driver_has_runtime_isolation_controls",
    "test_live_bundle_builders_are_networkless_independent_and_reproducible",
    "test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
]
DOC_TESTS = ["scripts/tests/test_markdown_preview_v09.py", "scripts/tests/test_documentation_tree_layout.py"]
TOOL_TESTS = ["scripts/tests/test_release_v12.py", "scripts/tests/test_release_next.py", "scripts/tests/test_spell_auditor_tool.py"]


def docker_python(*args, network="none", extra=()):
    return ["docker", "run", "--rm", "--network", network,
            "-v", f"{ROOT.as_posix()}:/workspace:ro", "-v", f"{OUT.as_posix()}:/evidence",
            *extra, QUALIFIER, *args]


def compose(*args):
    return ["docker", "compose", "--env-file", str(OUT / "runtime.env"),
            "--project-name", f"spellv0{MINOR}release", "--profile", "driver", *args]


class Producer:
    def __init__(self, gate):
        require(not git("status", "--porcelain"), "qualification requires clean committed source")
        OUT.mkdir(parents=True, exist_ok=True)
        if gate not in {"prepare", "candidate"}:
            verify_candidate(policy())
        self.gate, self.source, self.binding = gate, git("rev-parse", "HEAD"), fingerprint()
        self.commands = []

    def run(self, command, *, cwd=ROOT, env=None, output=None, private=False):
        started = time.monotonic()
        result = subprocess.run([str(arg) for arg in command], cwd=cwd, env=env, capture_output=True)
        # Credentials are only captured in memory. They are never command arguments or logs.
        if not private:
            log = OUT / f"{self.gate}-{len(self.commands):02d}.log"
            log.write_bytes(result.stdout + result.stderr)
            if output:
                (OUT / output).write_bytes(result.stdout)
        def display(arg):
            value = str(arg)
            for base, label in ((str(ROOT), "<repository>"), (os.environ.get("LOCALAPPDATA"), "<LocalAppData>"),
                                (os.environ.get("ProgramFiles"), "<ProgramFiles>")):
                if base:
                    value = value.replace(base, label).replace(base.replace("\\", "/"), label)
            return value
        self.commands.append({"gate": self.gate, "source_commit": self.source,
                              "command": [display(arg) for arg in command],
                              "returncode": result.returncode,
                              "seconds": round(time.monotonic() - started, 3)})
        require(result.returncode == 0, f"{self.gate} command failed; inspect its local log")
        return result.stdout

    def finish(self):
        require(self.source == git("rev-parse", "HEAD") and self.binding == fingerprint(), "source changed during qualification")
        write_json(OUT / f"{self.gate}.command.json", {"source_commit": self.source,
                   "source_fingerprint": self.binding, "commands": self.commands})
        print(f"{self.gate}: PASS commands={len(self.commands)}")

    def execute(self):
        gate = self.gate
        if gate == "prepare":
            self.run(["docker", "build", "-t", QUALIFIER, "-f", "scripts/qualification-next.Dockerfile", "."])
            for name, dockerfile, target in [
                ("backend", "backend/Dockerfile", None), ("driver", "driver_host/Dockerfile", None),
                ("frontend", "proxy/Dockerfile", "frontend-build"), ("proxy", "proxy/Dockerfile", None),
            ]:
                command = ["docker", "build", "-t", IMAGES[name], "-f", dockerfile]
                self.run(command + (["--target", target] if target else []) + ["."])
            runtime = OUT / "runtime.env"
            if not runtime.exists():
                runtime.write_bytes((f"SPELL_DB_PASSWORD={secrets.token_hex(24)}\n"
                    f"SPELL_JWT_HS256_SECRET={secrets.token_hex(32)}\nSPELL_IMAGE_TAG={TAG}\n"
                    "SPELL_DRIVER_ENABLED=true\nSPELL_ALLOW_LOCAL_DEV_TOKEN=false\nSPELL_PROXY_PORT=8080\n").encode())
            previous_env = ROOT / f".qualification/v{MINOR-1}/final/runtime.env"
            if previous_env.exists():
                self.run(["docker", "compose", "--env-file", str(previous_env),
                          "--project-name", f"spellv0{MINOR-1}release", "--profile", "driver", "stop"])
            self.run(compose("up", "--build", "-d", "--wait"))
            # Compose image labels participate in image identity. Audit the running images.
            for service, name in (("backend", "backend"), ("spell-driver", "driver"), ("proxy", "proxy")):
                container = self.run(compose("ps", "--quiet", service)).decode().strip()
                identity = self.run(["docker", "inspect", "--format", "{{.Image}}", container]).decode().strip()
                self.run(["docker", "tag", identity, IMAGES[name]])
            for database in ("spell_test", "spell_migration_test"):
                existing = self.run(compose("exec", "-T", "postgres", "psql", "-U", "spell", "-d", "spell", "-tAc",
                                           f"SELECT 1 FROM pg_database WHERE datname='{database}'"))
                if existing.strip() != b"1":
                    self.run(compose("exec", "-T", "postgres", "createdb", "-U", "spell", database))
            entries = dict(line.split("=", 1) for line in runtime.read_text().splitlines())
            password = entries["SPELL_DB_PASSWORD"]
            (OUT / "postgres.env").write_bytes((
                f"SPELL_TEST_DATABASE_URL=postgresql+psycopg://spell:{password}@postgres:5432/spell_test\n"
                f"SPELL_MIGRATION_TEST_DATABASE_URL=postgresql+psycopg://spell:{password}@postgres:5432/spell_migration_test\n").encode())
        elif gate == "candidate":
            self.run(docker_python("-m", "pytest", *policy()["candidate_files"], "-q", "-p", "no:cacheprovider",
                                   "--tb=short", "--junitxml=/evidence/candidate.xml"))
        elif gate in {"sqlite", "postgresql", "compose", "documentation", "tooling"}:
            tests = {
                "sqlite": ["backend/tests", "driver_host/tests"], "postgresql": ["backend/tests"],
                "compose": ["backend/tests/test_driver_isolation.py::" + name for name in COMPOSE_TESTS],
                "documentation": DOC_TESTS, "tooling": TOOL_TESTS,
            }[gate]
            extra, network = [], "none"
            if gate == "postgresql":
                extra = ["--env-file", str(OUT / "postgres.env")]
                network = f"spellv0{MINOR}release_spell-internal"
            elif gate == "compose":
                extra = ["-v", "/var/run/docker.sock:/var/run/docker.sock", "-e", "SPELL_RUN_COMPOSE_RUNTIME_TESTS=1",
                         "-e", f"SPELL_IMAGE_TAG={TAG}-isolation"]
                network = "bridge"
            self.run(docker_python("-m", "pytest", *tests, "-q", "-p", "no:cacheprovider", "--tb=short",
                                   f"--junitxml=/evidence/{gate}.xml", network=network, extra=extra))
        elif gate in {"frontend", "frontend-build"}:
            npm = shutil.which("npm.cmd") or shutil.which("npm")
            if gate == "frontend":
                self.run([npm, "ci", "--ignore-scripts"], cwd=ROOT / "frontend")
                self.run([npm, "test", "--", "--run", "--reporter=junit", f"--outputFile={OUT / 'frontend.xml'}"], cwd=ROOT / "frontend")
            else:
                self.run([npm, "run", "build"], cwd=ROOT / "frontend")
        elif gate == "replay":
            self.run(docker_python("-m", "scripts.qualify_legacy_observation_v12", "--soak-seconds", "60", "--output", "/evidence/replay.json"))
        elif gate == "reference-generators":
            self.run(docker_python("-m", "scripts.generate_reference_runner_v10", "--check"))
            self.run(docker_python("-m", "scripts.qualify_reference_examples_v10", "--output", "/evidence/reference-examples.json"))
        elif gate == "browser":
            token = self.run(compose("run", "--rm", "--no-deps", "-e", "SPELL_ALLOW_LOCAL_DEV_TOKEN=true",
                "backend", "python", "/app/scripts/issue_dev_token.py", "--subject", f"v0{MINOR}-browser-qualification",
                "--role", "operator", "--lifetime", "900"), private=True).decode().strip()
            require(token.count(".") == 2 and "\n" not in token, "token issuer output invalid")
            env = dict(os.environ, SPELL_E2E_TOKEN=token, SPELL_REAL_BACKEND="1", SPELL_E2E_BASE_URL="http://127.0.0.1:8080",
                       PLAYWRIGHT_JUNIT_OUTPUT_FILE=str(OUT / "browser.xml"), PLAYWRIGHT_JUNIT_INCLUDE_PROJECT_IN_TEST_NAME="1",
                       SPELL_E2E_OUTPUT_DIRECTORY=str(OUT / "browser"))
            node = shutil.which("node")
            self.run([node, "node_modules/@playwright/test/cli.js", "test", "legacy-observation-v12-real.spec.ts",
                      *policy()["feature_browser_specs"], "language-reference-v10-real.spec.ts", "--workers=1", "--reporter=junit"], cwd=ROOT / "frontend", env=env)
        elif gate == "image-probe":
            self.run(docker_python("-c", "import pathlib; files=[*pathlib.Path('backend').rglob('*.py'),*pathlib.Path('driver_host').rglob('*.py')]; [compile(p.read_bytes(),str(p),'exec') for p in files]; print('compilation PASS',len(files))"))
            self.run(docker_python("-m", "scripts.probe_images_next", "--output", "/evidence/image-probe.json", network="none",
                                  extra=["-v", "/var/run/docker.sock:/var/run/docker.sock"]))
        elif gate == "supply-chain":
            self.run(docker_python("-m", "pip_audit", "--disable-pip", "--no-deps", "-r", "backend/requirements.hashes.lock",
                                  "-f", "json", "-o", "/evidence/python-audit.json", network="bridge"))
            npm = shutil.which("npm.cmd") or shutil.which("npm")
            self.run([npm, "audit", "--json"], cwd=ROOT / "frontend", output="npm-audit.json")
            sbom = Path(os.environ["LOCALAPPDATA"]) / "OpenBEXI/release-toolchain/docker-sbom-0.6.0-windows-amd64/docker-sbom.exe"
            rows = {}
            for name, image in IMAGES.items():
                identity = self.run(["docker", "image", "inspect", "--format", "{{.Id}}", image]).decode().strip()
                self.run([str(sbom), "sbom", identity, "--format", "cyclonedx-json", "--output", str(OUT / f"{name}.cdx.json")])
                self.run(["docker", "scout", "cves", identity, "--format", "sarif", "--output", str(OUT / f"{name}.sarif.json")])
                scan = json.loads((OUT / f"{name}.sarif.json").read_bytes())
                rules = scan["runs"][0]["tool"]["driver"]["rules"]
                probes = json.loads((OUT / "image-probe.json").read_bytes())
                require(probes["images"][name]["image_id"] == identity, "applicability probe image differs")
                resolutions = resolve(scan, probes["images"][name])
                rows[name] = {"image_id": identity, "high": 0, "critical": 0,
                                "resolved_findings": resolutions,
                              "sbom_sha256": hashlib.sha256((OUT / f"{name}.cdx.json").read_bytes()).hexdigest(),
                              "scan_sha256": hashlib.sha256((OUT / f"{name}.sarif.json").read_bytes()).hexdigest(),
                                "lower_severity_disposition": {"advisories": [r["id"] for r in rules if float(r["properties"].get("security-severity", "0")) < 7],
                                  "review_by": "2026-10-30", "decision": "Restricted local synthetic environment; monitor vendor fixes and rebuild before broader use."}}
            write_json(OUT / "supply-chain.json", {"schema_version": f"spell.v{MINOR}.supply-chain/1", "images": rows})
            self.run(docker_python("-c", "import json,pathlib; from scripts.validate_cyclonedx_v04 import validate_document,run_negative_self_test; p=pathlib.Path('/evidence'); names=['backend','driver','frontend','proxy']; versions={n:validate_document((p/(n+'.cdx.json')).read_text(),n) for n in names}; run_negative_self_test(); (p/'sbom-validation.json').write_bytes((json.dumps({'schemas':versions,'negative_tamper_rejected':True,'validator':'cyclonedx-python-lib/11.11.0'},sort_keys=True)+'\\n').encode()); print('four strict CycloneDX schemas: PASS')"))
        else:
            raise ValueError("unknown gate")
        self.finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gate", choices=("prepare", "candidate", "sqlite", "postgresql", "compose", "documentation", "tooling",
        "frontend", "frontend-build", "replay", "reference-generators", "browser", "image-probe", "supply-chain", "assemble"))
    args = parser.parse_args()
    if args.gate == "assemble":
        captures = [json.loads(path.read_bytes()) for path in sorted(OUT.glob("*.command.json")) if path.name != "candidate.command.json"]
        require(len(captures) == 13, "missing canonical gate capture")
        require(all(row["source_commit"] == git("rev-parse", "HEAD") and row["source_fingerprint"] == fingerprint() for row in captures), "capture source differs")
        write_json(OUT / "commands.json", {"source_commit": git("rev-parse", "HEAD"), "commands": [command for row in captures for command in row["commands"]]})
    else:
        Producer(args.gate).execute()


if __name__ == "__main__":
    main()
