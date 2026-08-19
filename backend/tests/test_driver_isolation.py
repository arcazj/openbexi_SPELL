from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = ROOT / "compose.yaml"


def _compose() -> dict[str, Any]:
    loaded = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _volume_source(value: str) -> str:
    return value.split(":", 1)[0]


def _volume_target(value: str) -> str:
    fields = value.split(":")
    assert len(fields) >= 2
    return fields[1]


def test_compose_statically_isolates_and_hardens_the_driver() -> None:
    compose = _compose()
    services = compose["services"]
    driver = services["spell-driver"]

    assert "ports" not in driver
    assert "expose" not in driver
    assert driver["networks"] == ["spell-driver-internal"]
    assert compose["networks"]["spell-driver-internal"]["internal"] is True
    assert "spell-driver-internal" in services["backend"]["networks"]
    assert "spell-driver-internal" not in services["proxy"]["networks"]
    assert "spell-driver-internal" not in services["postgres"]["networks"]
    assert services["backend"]["networks"]["spell-internal"]["aliases"] == [
        "spell-api"
    ]

    assert driver["user"] == "10002:10002"
    assert driver["read_only"] is True
    assert driver["cap_drop"] == ["ALL"]
    assert "cap_add" not in driver
    assert driver["security_opt"] == ["no-new-privileges:true"]
    assert driver["pids_limit"] == 64
    assert driver["mem_limit"] == "256m"
    assert float(driver["cpus"]) == 1.0
    assert driver["stop_signal"] == "SIGINT"
    assert driver["stop_grace_period"] == "2s"
    assert driver["tmpfs"] == ["/tmp:size=32m,noexec,nosuid"]

    volumes = driver["volumes"]
    assert {
        (_volume_source(value), _volume_target(value), value.endswith(":ro"))
        for value in volumes
    } == {
        (
            "spell-driver-server-credentials",
            "/run/spell-driver-server",
            True,
        ),
        ("spell-driver-journal", "/var/lib/spell-driver", False),
    }
    assert "spell-postgres-data" not in {
        _volume_source(value) for value in volumes
    }
    assert "DATABASE_URL" not in driver.get("environment", {})


def test_compose_physically_separates_gateway_and_server_credentials() -> None:
    services = _compose()["services"]
    initializer = services["pki-init"]
    backend = services["backend"]
    backend_sources = {
        _volume_source(value) for value in services["backend"]["volumes"]
    }
    driver_sources = {
        _volume_source(value) for value in services["spell-driver"]["volumes"]
    }

    assert "spell-driver-client-credentials" in backend_sources
    assert "spell-driver-server-credentials" not in backend_sources
    assert "spell-driver-journal" not in backend_sources
    assert "spell-driver-server-credentials" in driver_sources
    assert "spell-driver-client-credentials" not in driver_sources

    assert backend["user"] == "0:0"
    assert backend["cap_drop"] == ["ALL"]
    assert set(backend["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"}
    assert backend["security_opt"] == ["no-new-privileges:true"]
    assert backend["healthcheck"]["test"] == [
        "CMD",
        "python",
        "/app/backend/healthcheck.py",
    ]
    assert (
        "/run/spell-driver-client:rw,noexec,nosuid,nodev,size=64k,"
        "mode=0700,uid=10001,gid=10001"
    ) in backend["tmpfs"]
    assert backend["volumes"] == [
        "spell-driver-client-credentials:/run/spell-driver-client-source:ro",
        "spell-data:/var/lib/openbexi-spell/data",
        "spell-migration-backups:/var/lib/openbexi-spell/migration-backups",
        "spell-bundle-builder-requests:/var/lib/openbexi-spell/builder/requests",
        "spell-bundle-builder-response-a:/var/lib/openbexi-spell/builder/responses-a",
        "spell-bundle-builder-response-b:/var/lib/openbexi-spell/builder/responses-b",
    ]

    assert initializer["network_mode"] == "none"
    assert initializer["read_only"] is True
    assert initializer["cap_drop"] == ["ALL"]
    assert set(initializer["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER"}
    assert initializer["security_opt"] == ["no-new-privileges:true"]
    assert "--force" not in initializer["command"]
    assert "/run/spell-driver-client-source" in initializer["command"]
    assert initializer["volumes"][0] == (
        "spell-driver-client-credentials:/run/spell-driver-client-source"
    )

    backend_dockerfile = (ROOT / "backend/Dockerfile").read_text(encoding="utf-8")
    driver_dockerfile = (ROOT / "driver_host/Dockerfile").read_text(
        encoding="utf-8"
    )
    assert "\nUSER 10001:10001\n" in backend_dockerfile
    assert (
        'ENTRYPOINT ["python", "/app/backend/credential_bootstrap.py"]'
        in backend_dockerfile
    )
    assert '"--host", "spell-api"' in backend_dockerfile
    assert '"--host", "0.0.0.0"' not in backend_dockerfile
    assert "\nUSER 10002:10002\n" in driver_dockerfile
    assert "\nSTOPSIGNAL SIGINT\n" in driver_dockerfile


def test_compose_statically_isolates_independent_bundle_builders() -> None:
    compose = _compose()
    services = compose["services"]
    backend = services["backend"]
    workers = {
        "builder-a": services["bundle-builder-a"],
        "builder-b": services["bundle-builder-b"],
    }
    assert {backend["image"], *(worker["image"] for worker in workers.values())} == {
        "openbexi-spell-backend:${SPELL_IMAGE_TAG:-local}"
    }
    assert all("build" not in worker for worker in workers.values())
    assert backend["depends_on"]["bundle-builder-a"]["condition"] == "service_healthy"
    assert backend["depends_on"]["bundle-builder-b"]["condition"] == "service_healthy"

    expected_responses = {
        "builder-a": "spell-bundle-builder-response-a",
        "builder-b": "spell-bundle-builder-response-b",
    }
    for worker_id, worker in workers.items():
        assert worker["entrypoint"] == [
            "python",
            "-m",
            "backend.development_bundle_worker",
        ]
        assert worker["network_mode"] == "none"
        assert worker["user"] == "10001:10001"
        assert worker["read_only"] is True
        assert worker["cap_drop"] == ["ALL"]
        assert worker["security_opt"] == ["no-new-privileges:true"]
        assert worker["pids_limit"] == 32
        assert worker["mem_limit"] == "512m"
        assert float(worker["cpus"]) == 0.5
        assert worker["tmpfs"] == ["/tmp:size=32m,noexec,nosuid,nodev"]
        assert worker["environment"]["SPELL_BUNDLE_BUILDER_WORKER_ID"] == worker_id
        assert not any(
            name.startswith(("DATABASE_", "SPELL_JWT_", "SPELL_DRIVER_"))
            for name in worker["environment"]
        )
        volumes = {
            (_volume_source(value), _volume_target(value), value.endswith(":ro"))
            for value in worker["volumes"]
        }
        assert volumes == {
            (
                "spell-bundle-builder-requests",
                "/var/lib/openbexi-spell/builder/requests",
                True,
            ),
            (
                expected_responses[worker_id],
                "/var/lib/openbexi-spell/builder/responses",
                False,
            ),
        }
        assert not any("docker.sock" in value for value in worker["volumes"])

    dockerfile = (ROOT / "backend/Dockerfile").read_text(encoding="utf-8")
    from backend.development_bundle_provenance import BASE_IMAGE_REFERENCE

    assert dockerfile.splitlines()[0] == f"FROM {BASE_IMAGE_REFERENCE}"
    assert "COPY backend /app/backend" in dockerfile
    assert f'org.opencontainers.image.base.name="{BASE_IMAGE_REFERENCE}"' in dockerfile


def test_gateway_consumes_credentials_before_the_application_accepts_work() -> None:
    tree = ast.parse((ROOT / "backend/app.py").read_text(encoding="utf-8"))
    gateway_start_lines = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Await)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and isinstance(node.value.func.value, ast.Name)
        and node.value.func.value.id == "driver_gateway"
        and node.value.func.attr == "start"
    ]
    application_yield_lines = [
        node.lineno for node in ast.walk(tree) if isinstance(node, ast.Yield)
    ]
    assert len(gateway_start_lines) == 1
    assert len(application_yield_lines) == 1
    assert gateway_start_lines[0] < application_yield_lines[0]


def test_spawned_worker_has_no_driver_product_call_path_or_credential_argument() -> None:
    worker_tree = ast.parse(
        (ROOT / "backend/worker.py").read_text(encoding="utf-8")
    )
    imported_modules = {
        alias.name
        for node in ast.walk(worker_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(worker_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not any(
        module == "grpc"
        or module.startswith("spell.driver")
        or module.startswith("backend.driver")
        or module in {"httpx", "requests", "socket", "urllib"}
        for module in imported_modules
    )

    worker_main = next(
        node
        for node in ast.walk(worker_tree)
        if isinstance(node, ast.FunctionDef) and node.name == "worker_main"
    )
    worker_arguments = [argument.arg for argument in worker_main.args.args]
    assert worker_arguments[:10] == [
        "execution_id",
        "generation",
        "ir_version",
        "steps",
        "start_step",
        "start_command_id",
        "resume_prompt_id",
        "checkpoint_variables",
        "control",
        "output",
    ]
    assert set(worker_arguments[10:]) <= {
        "resume_prompt_settlement",
        "resume_startproc_result",
        "registered_user_action_invocations",
        "durable_arguments",
        "safe_point_ack_required",
    }
    assert not any(
        marker in argument.lower()
        for argument in worker_arguments
        for marker in ("credential", "password", "secret", "token", "driver")
    )

    supervisor_tree = ast.parse(
        (ROOT / "backend/supervisor.py").read_text(encoding="utf-8")
    )
    process_calls = [
        node
        for node in ast.walk(supervisor_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "Process"
    ]
    assert len(process_calls) == 1
    keywords = {item.arg: item.value for item in process_calls[0].keywords}
    assert isinstance(keywords["target"], ast.Name)
    assert keywords["target"].id == "worker_main"
    assert isinstance(keywords["args"], ast.Tuple)
    process_arguments = [
        item.id for item in keywords["args"].elts if isinstance(item, ast.Name)
    ]
    assert process_arguments[:10] == [
        "execution_id",
        "generation",
        "ir_version",
        "steps",
        "start_step",
        "command_id",
        "resume_prompt_id",
        "checkpoint_variables",
        "control",
        "output",
    ]
    assert set(process_arguments[10:]) <= {
        "resume_prompt_settlement",
        "resume_startproc_result",
        "registered_user_action_invocations",
        "durable_arguments",
        "safe_point_ack_required",
    }


def test_spawned_worker_starts_without_service_secrets_or_inherited_files(
    client: TestClient,
    operator_headers: dict[str, str],
    viewer_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if not Path("/proc/self/environ").is_file():
        pytest.skip("the process environment probe requires Linux /proc")

    canary = "spell-worker-secret-canary-7d86b03e"
    inherited_names = (
        "DATABASE_URL",
        "SPELL_JWT_HS256_SECRET",
        "SPELL_DRIVER_CLIENT_KEY_PATH",
        "SPELL_SERVICE_CANARY",
        "HTTPS_PROXY",
    )
    for name in inherited_names:
        monkeypatch.setenv(name, f"{canary}-{name.lower()}")

    canary_path = tmp_path / "inherited-service-credential.canary"
    canary_path.write_text(canary, encoding="ascii")
    descriptor = os.open(canary_path, os.O_RDONLY)
    os.set_inheritable(descriptor, True)
    try:
        response = client.post(
            "/api/v1/executions",
            headers=operator_headers,
            json={
                "procedure_id": "pause",
                "context_id": "simulator",
                "reason": "worker environment boundary probe",
                "idempotency_key": "worker-environment-boundary-probe",
            },
        )
        assert response.status_code == 202, response.text
        execution_id = response.json()["execution"]["id"]

        deadline = time.monotonic() + 5
        handle = None
        while time.monotonic() < deadline:
            handle = client.app.state.supervisor._workers.get(execution_id)
            if handle is not None and handle.process.is_alive():
                break
            time.sleep(0.02)
        assert handle is not None and handle.process.is_alive()

        environment = Path(f"/proc/{handle.process.pid}/environ").read_bytes()
        assert canary.encode("ascii") not in environment
        assert all(f"{name}=".encode("ascii") not in environment for name in inherited_names)

        inherited_targets = []
        for entry in Path(f"/proc/{handle.process.pid}/fd").iterdir():
            try:
                inherited_targets.append(os.readlink(entry))
            except OSError:
                continue
        assert str(canary_path) not in inherited_targets

        while time.monotonic() < deadline:
            snapshot = client.get(
                f"/api/v1/executions/{execution_id}/snapshot", headers=viewer_headers
            ).json()
            if snapshot["execution"]["state"] in {"running", "completed"}:
                break
            time.sleep(0.02)
        assert snapshot["execution"]["state"] in {"running", "completed"}
    finally:
        os.close(descriptor)


def _docker_compose(
    project: str, arguments: list[str], *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.update(
        {
            "BUILDKIT_PROGRESS": "plain",
            "SPELL_ALLOW_LOCAL_DEV_TOKEN": "true",
            "SPELL_DB_PASSWORD": "compose-isolation-test",
            "SPELL_DRIVER_ENABLED": "true",
            "SPELL_JWT_HS256_SECRET": "compose-isolation-test-secret-32-bytes",
        }
    )
    return subprocess.run(
        [
            "docker",
            "compose",
            "--project-directory",
            str(ROOT),
            "--file",
            str(COMPOSE_PATH),
            "--project-name",
            project,
            "--profile",
            "driver",
            *arguments,
        ],
        cwd=ROOT,
        env=environment,
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )


def test_created_compose_driver_has_runtime_isolation_controls() -> None:
    if os.environ.get("SPELL_RUN_COMPOSE_RUNTIME_TESTS") != "1":
        pytest.skip("set SPELL_RUN_COMPOSE_RUNTIME_TESTS=1 for Docker inspection")
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI is unavailable")

    project = f"spell-v04-isolation-{uuid.uuid4().hex[:12]}"
    try:
        _docker_compose(
            project,
            ["create", "--build", "pki-init", "spell-driver"],
        )
        _docker_compose(
            project,
            [
                "up",
                "--detach",
                "--wait",
                "--wait-timeout",
                "60",
                "pki-init",
                "spell-driver",
            ],
        )
        container_id = _docker_compose(
            project, ["ps", "--all", "--quiet", "spell-driver"]
        ).stdout.strip()
        assert container_id
        inspected = subprocess.run(
            ["docker", "inspect", container_id],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        container = json.loads(inspected.stdout)[0]
        host = container["HostConfig"]

        assert container["State"]["Running"] is True
        assert container["State"]["Health"]["Status"] == "healthy"
        assert container["Config"]["User"] == "10002:10002"
        assert container["Config"]["StopSignal"] == "SIGINT"
        assert container["Config"].get("ExposedPorts") in (None, {})
        assert host.get("PortBindings") in (None, {})
        assert host["PublishAllPorts"] is False
        assert host["ReadonlyRootfs"] is True
        assert host["CapDrop"] == ["ALL"]
        assert host.get("CapAdd") in (None, [])
        assert host["SecurityOpt"] == ["no-new-privileges:true"]
        assert host["PidsLimit"] == 64
        assert host["Memory"] == 256 * 1024 * 1024
        assert host["NanoCpus"] == 1_000_000_000
        stop_timeout = container["Config"].get(
            "StopTimeout", host.get("StopTimeout")
        )
        assert stop_timeout == 2
        assert host.get("PidMode", "") == ""

        named_volumes = {
            mount["Destination"]: (mount["Name"], mount["RW"])
            for mount in container["Mounts"]
            if mount["Type"] == "volume"
        }
        assert set(named_volumes) == {
            "/run/spell-driver-server",
            "/var/lib/spell-driver",
        }
        assert named_volumes["/run/spell-driver-server"][1] is False
        assert named_volumes["/var/lib/spell-driver"][1] is True

        network_mode = host["NetworkMode"]
        network = json.loads(
            subprocess.run(
                ["docker", "network", "inspect", network_mode],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            ).stdout
        )[0]
        assert network["Internal"] is True
        assert set(container["NetworkSettings"]["Networks"]) == {network_mode}
    finally:
        _docker_compose(
            project,
            ["down", "--volumes", "--remove-orphans"],
            check=False,
        )


def _docker_exec(
    container_id: str,
    arguments: list[str],
    *,
    user: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    command = ["docker", "exec"]
    if user is not None:
        command.extend(["--user", user])
    command.extend([container_id, *arguments])
    return subprocess.run(
        command,
        cwd=ROOT,
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )


def _inspect_container(container_id: str) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "inspect", container_id],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    return json.loads(result.stdout)[0]


def test_live_bundle_builders_are_networkless_independent_and_reproducible() -> None:
    if os.environ.get("SPELL_RUN_COMPOSE_RUNTIME_TESTS") != "1":
        pytest.skip("set SPELL_RUN_COMPOSE_RUNTIME_TESTS=1 for Docker inspection")
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI is unavailable")

    project = f"spell-v09-bundle-builders-{uuid.uuid4().hex[:12]}"
    try:
        _docker_compose(project, ["build", "backend"])
        _docker_compose(
            project,
            [
                "up",
                "--detach",
                "--no-build",
                "--wait",
                "--wait-timeout",
                "90",
                "bundle-builder-a",
                "bundle-builder-b",
            ],
        )
        container_ids = {
            service: _docker_compose(
                project, ["ps", "--quiet", service]
            ).stdout.strip()
            for service in ("bundle-builder-a", "bundle-builder-b")
        }
        assert all(container_ids.values())
        inspected = {
            service: _inspect_container(container_id)
            for service, container_id in container_ids.items()
        }
        assert len({value["Image"] for value in inspected.values()}) == 1
        expected_response = {
            "bundle-builder-a": "response-a",
            "bundle-builder-b": "response-b",
        }
        descriptor_digests = set()
        for service, container in inspected.items():
            host = container["HostConfig"]
            assert container["State"]["Running"] is True
            assert container["State"]["Health"]["Status"] == "healthy"
            assert container["Config"]["User"] == "10001:10001"
            assert host["NetworkMode"] == "none"
            assert host["ReadonlyRootfs"] is True
            assert host["CapDrop"] == ["ALL"]
            assert host.get("CapAdd") in (None, [])
            assert host["SecurityOpt"] == ["no-new-privileges:true"]
            assert host["PidsLimit"] == 32
            assert host["Memory"] == 512 * 1024 * 1024
            assert host["NanoCpus"] == 500_000_000
            networks = container["NetworkSettings"]["Networks"]
            assert set(networks) in (set(), {"none"})
            if networks:
                no_network = networks["none"]
                for field in (
                    "IPAddress",
                    "Gateway",
                    "GlobalIPv6Address",
                    "MacAddress",
                ):
                    assert no_network.get(field) in (None, "")
            mounts = {
                mount["Destination"]: (mount["Name"], mount["RW"])
                for mount in container["Mounts"]
                if mount["Type"] == "volume"
            }
            assert set(mounts) == {
                "/var/lib/openbexi-spell/builder/requests",
                "/var/lib/openbexi-spell/builder/responses",
            }
            assert mounts["/var/lib/openbexi-spell/builder/requests"][1] is False
            response_name = mounts["/var/lib/openbexi-spell/builder/responses"][0]
            assert expected_response[service] in response_name
            assert mounts["/var/lib/openbexi-spell/builder/responses"][1] is True
            environment = container["Config"].get("Env") or []
            assert not any(
                item.startswith(("DATABASE_URL=", "SPELL_JWT_", "SPELL_DRIVER_"))
                for item in environment
            )
            probe = _docker_exec(
                container_ids[service],
                [
                    "python",
                    "-c",
                    (
                        "from pathlib import Path; "
                        "assert Path('/app/backend/Dockerfile').is_file(); "
                        "from backend.development_bundle_provenance import toolchain_digest; "
                        "print(toolchain_digest())"
                    ),
                ],
            )
            descriptor_digests.add(probe.stdout.strip())
            denied = _docker_exec(
                container_ids[service],
                [
                    "python",
                    "-c",
                    (
                        "import socket; s=socket.socket(); s.settimeout(0.2); "
                        "s.connect(('192.0.2.1', 9))"
                    ),
                ],
                check=False,
            )
            assert denied.returncode != 0
        assert len(descriptor_digests) == 1

        client_code = """
import hashlib, json, os
from pathlib import Path
from backend.development_bundle_broker import DualContainerBundleBroker
from backend.tests.test_development_bundle_builder_v09 import _request
broker = DualContainerBundleBroker(
    request_directory=Path(os.environ["SPELL_BUNDLE_REQUEST_DIR"]),
    response_directories={
        "builder-a": Path(os.environ["SPELL_BUNDLE_RESPONSE_A_DIR"]),
        "builder-b": Path(os.environ["SPELL_BUNDLE_RESPONSE_B_DIR"]),
    },
    timeout_seconds=30,
)
first = broker.build(_request())
second = broker.build(_request())
assert first == second
print(json.dumps({
    "bundle_sha256": hashlib.sha256(first.bundle_bytes).hexdigest(),
    "byte_length": len(first.bundle_bytes),
    "toolchain_digest": first.toolchain_digest,
}, sort_keys=True))
"""
        result = _docker_compose(
            project,
            [
                "run",
                "--rm",
                "--no-deps",
                "--user",
                "10001:10001",
                "--entrypoint",
                "python",
                "backend",
                "-c",
                client_code,
            ],
        )
        proof = json.loads(result.stdout.strip().splitlines()[-1])
        assert proof["byte_length"] > 0
        assert proof["bundle_sha256"]
        assert proof["toolchain_digest"] in descriptor_digests
    finally:
        _docker_compose(
            project,
            ["down", "--volumes", "--remove-orphans"],
            check=False,
        )


def _backend_api(
    container_id: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    code = """
import json, sys, urllib.request
from backend.auth import AuthConfig, issue_local_dev_token
token = issue_local_dev_token(
    AuthConfig.from_env(), subject="restart-isolation-probe", role="operator",
    peer_host="127.0.0.1", lifetime_seconds=60,
)
body = None if sys.argv[3] == "" else sys.argv[3].encode("utf-8")
request = urllib.request.Request(
    "http://spell-api:8000" + sys.argv[2], data=body, method=sys.argv[1],
    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Host": "127.0.0.1"},
)
with urllib.request.urlopen(request, timeout=5) as response:
    print(response.read().decode("utf-8"))
"""
    encoded = "" if payload is None else json.dumps(payload, separators=(",", ":"))
    result = _docker_exec(
        container_id,
        ["python", "-c", code, method, path, encoded],
    )
    loaded = json.loads(result.stdout)
    assert isinstance(loaded, dict)
    return loaded


def _process_statuses(container_id: str) -> dict[str, Any]:
    code = """
import json
from pathlib import Path
keys = {"Uid", "Gid", "Groups", "CapPrm", "CapEff", "CapAmb"}
def status(pid):
    result = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition(":")
        if separator and key in keys:
            fields = value.split()
            result[key] = [int(item) for item in fields] if key in {"Uid", "Gid", "Groups"} else fields[0]
    return result
children = sorted({
    int(item)
    for child_file in Path("/proc/1/task").glob("*/children")
    for item in child_file.read_text().split()
})
print(json.dumps({"pid1": status(1), "children": [status(pid) for pid in children]}, sort_keys=True))
"""
    return json.loads(_docker_exec(container_id, ["python", "-c", code]).stdout)


def _credential_mount_status(container_id: str) -> dict[str, Any]:
    code = """
import hashlib, json, stat
from pathlib import Path
source = Path("/run/spell-driver-client-source")
runtime = Path("/run/spell-driver-client")
digests = {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in ("ca.crt", "client.crt", "client.key")}
def mount(target):
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if fields[4] == target:
            separator = fields.index("-")
            return {"options": fields[5].split(","), "filesystem": fields[separator + 1]}
    raise RuntimeError("expected credential mount is absent")
key = (source / "client.key").stat()
runtime_stat = runtime.stat()
print(json.dumps({
    "bundle_digest": hashlib.sha256(json.dumps(digests, sort_keys=True).encode("ascii")).hexdigest(),
    "client_certificate_digest": digests["client.crt"],
    "source_key_uid": key.st_uid,
    "source_key_gid": key.st_gid,
    "source_key_mode": stat.S_IMODE(key.st_mode),
    "source_directory_mode": stat.S_IMODE(source.stat().st_mode),
    "runtime_directory_uid": runtime_stat.st_uid,
    "runtime_directory_gid": runtime_stat.st_gid,
    "runtime_directory_mode": stat.S_IMODE(runtime_stat.st_mode),
    "runtime_entries": sorted(item.name for item in runtime.iterdir()),
    "source_mount": mount(str(source)),
    "runtime_mount": mount(str(runtime)),
}, sort_keys=True))
"""
    return json.loads(_docker_exec(container_id, ["python", "-c", code]).stdout)


def _assert_unprivileged_status(status: dict[str, Any]) -> None:
    assert status["Uid"] == [10001, 10001, 10001, 10001]
    assert status["Gid"] == [10001, 10001, 10001, 10001]
    assert status["Groups"] == []
    assert status["CapPrm"] == "0000000000000000"
    assert status["CapEff"] == "0000000000000000"
    assert status["CapAmb"] == "0000000000000000"


def _wait_for_backend_health(container_id: str) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        inspected = _inspect_container(container_id)
        if inspected["State"].get("Health", {}).get("Status") == "healthy":
            return
        time.sleep(0.5)
    raise AssertionError("backend did not become healthy")


def _wait_for_ready_driver(container_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = _backend_api(container_id, "GET", "/api/v1/drivers")
        items = latest.get("items")
        if isinstance(items, list) and len(items) == 1 and items[0]["state"] == "READY":
            return items[0]
        time.sleep(0.25)
    raise AssertionError(f"driver did not become ready: {latest!r}")


def test_backend_restart_reuses_same_epoch_with_no_worker_credential_access() -> None:
    if os.environ.get("SPELL_RUN_COMPOSE_RUNTIME_TESTS") != "1":
        pytest.skip("set SPELL_RUN_COMPOSE_RUNTIME_TESTS=1 for Docker inspection")
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI is unavailable")

    project = f"spell-v04-restart-{uuid.uuid4().hex[:12]}"
    try:
        _docker_compose(
            project,
            [
                "up",
                "--detach",
                "--build",
                "--wait",
                "--wait-timeout",
                "90",
                "postgres",
                "pki-init",
                "spell-driver",
                "backend",
            ],
        )
        backend_id = _docker_compose(project, ["ps", "--quiet", "backend"]).stdout.strip()
        pki_id = _docker_compose(project, ["ps", "--all", "--quiet", "pki-init"]).stdout.strip()
        assert backend_id and pki_id
        _wait_for_backend_health(backend_id)
        before_driver = _wait_for_ready_driver(backend_id)
        before_credentials = _credential_mount_status(backend_id)
        inspected_pki = _inspect_container(pki_id)
        before_pki = {
            "StartedAt": inspected_pki["State"]["StartedAt"],
            "FinishedAt": inspected_pki["State"]["FinishedAt"],
            "RestartCount": inspected_pki["RestartCount"],
        }

        assert before_credentials["source_key_uid"] == 0
        assert before_credentials["source_key_gid"] == 0
        assert before_credentials["source_key_mode"] == 0o400
        assert before_credentials["source_directory_mode"] == 0o700
        assert before_credentials["runtime_directory_uid"] == 10001
        assert before_credentials["runtime_directory_gid"] == 10001
        assert before_credentials["runtime_directory_mode"] == 0o700
        assert before_credentials["runtime_entries"] == ["ca.crt", "client.crt"]
        assert before_credentials["source_mount"]["options"][0] == "ro"
        assert before_credentials["runtime_mount"]["filesystem"] == "tmpfs"
        assert {"rw", "noexec", "nosuid", "nodev"}.issubset(
            before_credentials["runtime_mount"]["options"]
        )
        _assert_unprivileged_status(_process_statuses(backend_id)["pid1"])

        denied = _docker_exec(
            backend_id,
            [
                "python",
                "-c",
                "from pathlib import Path; Path('/run/spell-driver-client-source/client.key').read_bytes()",
            ],
            user="10001:10001",
            check=False,
        )
        assert denied.returncode != 0

        _backend_api(
            backend_id,
            "POST",
            "/api/v1/executions",
            {
                "procedure_id": "language_reference_244",
                "context_id": "simulator",
                "reason": "credential restart isolation probe",
                "idempotency_key": f"restart-isolation-{uuid.uuid4()}",
            },
        )
        deadline = time.monotonic() + 10
        statuses = _process_statuses(backend_id)
        while not statuses["children"] and time.monotonic() < deadline:
            time.sleep(0.1)
            statuses = _process_statuses(backend_id)
        assert statuses["children"]
        for child in statuses["children"]:
            _assert_unprivileged_status(child)
        assert _credential_mount_status(backend_id)["runtime_entries"] == [
            "ca.crt",
            "client.crt",
        ]

        subprocess.run(
            ["docker", "restart", "--time", "10", backend_id],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        _wait_for_backend_health(backend_id)
        after_driver = _wait_for_ready_driver(backend_id)
        after_credentials = _credential_mount_status(backend_id)
        inspected_pki = _inspect_container(pki_id)
        after_pki = {
            "StartedAt": inspected_pki["State"]["StartedAt"],
            "FinishedAt": inspected_pki["State"]["FinishedAt"],
            "RestartCount": inspected_pki["RestartCount"],
        }

        assert after_driver["credential_epoch"] == before_driver["credential_epoch"]
        assert after_driver["last_observed_at"] > before_driver["last_observed_at"]
        assert after_credentials == before_credentials
        assert after_pki["StartedAt"] == before_pki["StartedAt"]
        assert after_pki["FinishedAt"] == before_pki["FinishedAt"]
        assert after_pki["RestartCount"] == before_pki["RestartCount"]
        _assert_unprivileged_status(_process_statuses(backend_id)["pid1"])
    finally:
        _docker_compose(
            project,
            ["down", "--volumes", "--remove-orphans"],
            check=False,
        )
