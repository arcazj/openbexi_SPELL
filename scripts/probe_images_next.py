"""Inspect the exact active release images and running local isolation boundaries."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
from scripts.release_next import VERSION, MINOR, TAG, PROJECT, PYTHON_RELEASE, image_names, verify_running_image_bindings


def call(*args):
    return subprocess.check_output(["docker", *args], stderr=subprocess.PIPE).decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    images = {}
    for name in sorted(image_names()):
        image = f"openbexi-spell-{name}:{TAG}"
        identity = json.loads(call("image", "inspect", image))[0]
        image = identity["Id"]
        if name == "python":
            assert identity["Config"]["User"] == "0:0"  # Trusted launcher drops child identity after chroot.
        else:
            assert identity["Config"]["User"] not in ("", "root", "0", "0:0")
        root = "/app" if name in {"backend", "driver", "dss", "python"} else "/src/frontend" if name == "frontend" else "/opt/kafka" if name == "kafka" else "/usr/share/nginx/html"
        files = call("run", "--rm", "--network", "none", "--entrypoint", "find", image, root, "-type", "f").splitlines()
        forbidden = [value for value in files if Path(value).suffix.lower() in {".pdf", ".zip", ".pyc", ".pyo", ".key", ".pem"}
                     or Path(value).name in {".env", "credentials.json", "secrets.json"}]
        assert not forbidden, (name, forbidden)
        row = {"image_id": identity["Id"], "user": identity["Config"]["User"], "product_files": len(files), "forbidden_files": []}
        if name in {"backend", "driver", "dss", "python"}:
            code = (Path(__file__).with_name("gcc_header_applicability.py")).read_text()
            row["gcc_header_applicability"] = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", code))
            if MINOR >= 18:
                code = (Path(__file__).with_name("gcc_aligned_new_applicability.py")).read_text()
                row["gcc_aligned_new_applicability"] = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", code))
            code = ("import hashlib,json,pathlib,zlib; p=pathlib.Path('/usr/lib/x86_64-linux-gnu/libz.so.1'); "
                    "print(json.dumps({'runtime_version':zlib.ZLIB_RUNTIME_VERSION,'library_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),"
                    "'upstream_commit':pathlib.Path('/usr/local/share/openbexi/zlib-source-commit').read_text().strip()}))")
            row["zlib"] = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", code))
            assert row["zlib"]["upstream_commit"] == "df84af25dc1942490e1d1c899a07619152a46148"
            assert row["zlib"]["runtime_version"] == "1.3.2.1-motley"
        if name == "dss":
            code = ("import json; from dss import SIMULATOR_VERSION,DYNAMICS_ENGINE_VERSION; "
                    "from dss.catalog import SatelliteDatabase; d=SatelliteDatabase.load(); "
                    "print(json.dumps({'simulator_version':SIMULATOR_VERSION,'dynamics_engine_version':DYNAMICS_ENGINE_VERSION,"
                    "'database_revision':d.revision,'database_digest':d.digest}))")
            row["dss_identity"] = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", code))
            from dss import SIMULATOR_VERSION, DYNAMICS_ENGINE_VERSION
            from dss.catalog import SatelliteDatabase
            database = SatelliteDatabase.load()
            assert row["dss_identity"] == {"simulator_version": SIMULATOR_VERSION, "dynamics_engine_version": DYNAMICS_ENGINE_VERSION,
                                            "database_revision": database.revision, "database_digest": database.digest}
        if name == "kafka":
            version = call("run", "--rm", "--network", "none", "--entrypoint", "/opt/kafka/bin/kafka-topics.sh", image, "--version").strip()
            assert version.split()[0] == "4.3.1"
            row["kafka_version"] = version
            row["java_version"] = call("run", "--rm", "--network", "none", "--entrypoint", "sh", image, "-c", "java -version 2>&1").strip()
            from scripts.generate_kafka_security_dockerfile import generated
            from scripts.kafka_security_inventory import LOCK_PATH, verify_inventory
            generated()  # Validate source coordinates before constructing container arguments.
            lock_bytes = Path("contracts/dss/kafka_dependency_lock.json").read_bytes()
            dependencies = json.loads(lock_bytes)["artifacts"]
            paths = ["/opt/kafka/libs/" + r["url"].rsplit("/", 1)[-1]
                     for r in dependencies if r["kind"] == "MAVEN"]
            hashes = {line.split()[1]: line.split()[0] for line in call("run", "--rm", "--network", "none",
                "--entrypoint", "sha256sum", image, *paths, LOCK_PATH).splitlines()}
            sizes = {line.split()[1]: int(line.split()[0]) for line in call("run", "--rm", "--network", "none",
                "--entrypoint", "wc", image, "-c", *paths).splitlines() if line.split()[1] != "total"}
            installed = [line.split()[0] for line in call("run", "--rm", "--network", "none", "--entrypoint",
                "apk", image, "list", "--installed", *[r["name"] for r in dependencies if r["kind"] == "APK"]).splitlines()]
            row["security_dependencies"] = verify_inventory(lock_bytes, hashes=hashes, sizes=sizes,
                installed_apks=installed, jar_files=[p for p in files if p.endswith(".jar")])
        if name == "backend":
            version = call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", "from backend.version import PRODUCT_VERSION; print(PRODUCT_VERSION)").strip()
            assert version == VERSION
            row["product_version"] = version
            contract = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c",
                                      "import json; from backend.synthetic_control import profile; print(json.dumps(profile()))"))
            assert contract["profile"] == "LOCAL_SYNTHETIC_PROCEDURE_CONTROL"
            row["control_profile"] = contract
            if MINOR >= 14:
                contract = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c",
                                          "import json; from backend.telemetry_adapter import profile; print(json.dumps(profile()))"))
                assert contract["profile"] == "LOCAL_SYNTHETIC_TELEMETRY_ADAPTER" and contract["mutability"] == "READ_ONLY"
                row["telemetry_profile"] = contract
            if MINOR >= 15:
                contract = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c",
                                          "import json; from backend.shadow_pilot import profile; print(json.dumps(profile()))"))
                assert contract["profile"] == "LOCAL_SYNTHETIC_SHADOW_PILOT" and contract["operational_authorization"] is False
                row["pilot_profile"] = contract
            if MINOR >= 16:
                language_module = f"backend.language_conformance_v{MINOR}"
                expected_ir = f"0.{MINOR}"
                code = (
                    "import json; from pathlib import Path; "
                    "from backend.procedure_parser import ProcedureCatalog; "
                    f"from {language_module} import execute_selection, CASES; "
                    "p=ProcedureCatalog(Path('/app/procedures')).get('language_reference_244'); "
                    f"assert p.ir_version=='{expected_ir}' and len(p.steps)==7; "
                    "summary,effects=execute_selection(195+len(CASES)); r=effects[0]['payload']; "
                    "assert len(r['cases'])==len(CASES) and all(c['passed'] for c in r['cases']); "
                    "assert len(r['adaptations'])==195 and sum(x['variant_count'] for x in r['adaptations'])==257; "
                    "assert r['full_compatibility'] is False; "
                    "print(json.dumps({'ir_version':p.ir_version,'steps':len(p.steps),"
                    "'direct_and_boundary_cases':len(r['cases']),'adapted_examples':len(r['adaptations']),"
                    "'adapted_variants':sum(x['variant_count'] for x in r['adaptations']),"
                    "'full_compatibility':r['full_compatibility'],'decision':'PASS'"
                    + (",'cases_sha256':r['cases_sha256']" if MINOR >= 17 else "") + "}))"
                )
                row["language_runner"] = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", code))
                if MINOR >= 17:
                    from importlib import import_module
                    assert row["language_runner"] == import_module(language_module).expected_image_runner_proof()
        if name == "python":
            code = "import json; from backend.native_python_protocol import READY; print(json.dumps(READY))"
            row["python_runtime"] = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", code))
            from backend.native_python_protocol import READY
            assert row["python_runtime"] == READY
            jail = call("run", "--rm", "--network", "none", "--entrypoint", "find", image, "/opt/spell-python", "-type", "f").splitlines()
            assert "/opt/spell-python/usr/local/lib/spell_python_debug.py" in jail
            assert not any("site-packages" in name or "/app/" in name or Path(name).suffix.lower() in {".pem", ".key", ".pdf", ".zip", ".pyc"} for name in jail)
        images[name] = row
    services = {}
    service_names = ("backend", "postgres", "spell-driver", "bundle-builder-a", "bundle-builder-b", "proxy")
    if MINOR >= 19:
        service_names += ("dss", "kafka")
    if PYTHON_RELEASE:
        service_names += ("python-runtime",)
    for service in service_names:
        ids = call("ps", "--filter", f"label=com.docker.compose.project={PROJECT}", "--filter", "label=com.docker.compose.service=" + service, "--format", "{{.ID}}").splitlines()
        assert len(ids) == 1
        info = json.loads(call("inspect", ids[0]))[0]
        host = info["HostConfig"]
        assert info["State"]["Running"]
        if service == "postgres":
            assert info["Config"]["User"] == "70:70"
            assert any(mount["Destination"] == "/var/lib/postgresql" and mount["Type"] == "volume" for mount in info["Mounts"])
        else:
            assert host["ReadonlyRootfs"] and "ALL" in host["CapDrop"]
        assert "no-new-privileges:true" in host["SecurityOpt"]
        ports = host.get("PortBindings") or {}
        if service == "dss":
            assert ports == {"3080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3080"}]}
        elif service != "proxy":
            assert not ports
        else:
            assert ports == {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
        if service == "python-runtime":
            assert host["NetworkMode"] == "none" and info["Config"]["User"] == "0:0"
            assert set(host["CapAdd"]) == {"CHOWN", "DAC_OVERRIDE", "SETUID", "SETGID", "SYS_CHROOT", "KILL"}
            assert host["Memory"] == 512 * 1024 * 1024 and host["PidsLimit"] == 64
        elif service.startswith("bundle-builder"):
            assert host["NetworkMode"] == "none"
        elif service != "proxy":
            for network in info["NetworkSettings"]["Networks"]:
                assert json.loads(call("network", "inspect", network))[0]["Internal"]
        services[service] = {"running": True, "read_only": host["ReadonlyRootfs"], "ports": ports, "image_id": info["Image"]}
    verify_running_image_bindings(services, images)
    args.output.write_bytes((json.dumps({"images": images, "services": services, "decision": "PASS"}, indent=2, sort_keys=True) + "\n").encode())
    print(f"{TAG} image and isolation probes: PASS")


if __name__ == "__main__":
    main()
