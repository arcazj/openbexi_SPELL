"""Inspect the exact active release images and running local isolation boundaries."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
from scripts.release_next import VERSION, MINOR, TAG


def call(*args):
    return subprocess.check_output(["docker", *args], stderr=subprocess.PIPE).decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    images = {}
    for name in ("backend", "driver", "frontend", "proxy"):
        image = f"openbexi-spell-{name}:{TAG}"
        identity = json.loads(call("image", "inspect", image))[0]
        assert identity["Config"]["User"] not in ("", "root", "0", "0:0")
        root = "/app" if name in {"backend", "driver"} else "/src/frontend" if name == "frontend" else "/usr/share/nginx/html"
        files = call("run", "--rm", "--network", "none", "--entrypoint", "find", image, root, "-type", "f").splitlines()
        forbidden = [value for value in files if Path(value).suffix.lower() in {".pdf", ".zip", ".pyc", ".pyo", ".key", ".pem"}
                     or Path(value).name in {".env", "credentials.json", "secrets.json"}]
        assert not forbidden, (name, forbidden)
        row = {"image_id": identity["Id"], "user": identity["Config"]["User"], "product_files": len(files), "forbidden_files": []}
        if name in {"backend", "driver"}:
            code = (Path(__file__).with_name("gcc_header_applicability.py")).read_text()
            row["gcc_header_applicability"] = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", code))
            code = ("import hashlib,json,pathlib,zlib; p=pathlib.Path('/usr/lib/x86_64-linux-gnu/libz.so.1'); "
                    "print(json.dumps({'runtime_version':zlib.ZLIB_RUNTIME_VERSION,'library_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),"
                    "'upstream_commit':pathlib.Path('/usr/local/share/openbexi/zlib-source-commit').read_text().strip()}))")
            row["zlib"] = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", code))
            assert row["zlib"]["upstream_commit"] == "df84af25dc1942490e1d1c899a07619152a46148"
            assert row["zlib"]["runtime_version"] == "1.3.2.1-motley"
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
        images[name] = row
    services = {}
    for service in ("backend", "postgres", "spell-driver", "bundle-builder-a", "bundle-builder-b", "proxy"):
        ids = call("ps", "--filter", f"label=com.docker.compose.project=spellv0{MINOR}release", "--filter", "label=com.docker.compose.service=" + service, "--format", "{{.ID}}").splitlines()
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
        if service != "proxy":
            assert not ports
        else:
            assert ports == {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
        if service.startswith("bundle-builder"):
            assert host["NetworkMode"] == "none"
        elif service != "proxy":
            for network in info["NetworkSettings"]["Networks"]:
                assert json.loads(call("network", "inspect", network))[0]["Internal"]
        services[service] = {"running": True, "read_only": host["ReadonlyRootfs"], "ports": ports, "image_id": info["Image"]}
    args.output.write_bytes((json.dumps({"images": images, "services": services, "decision": "PASS"}, indent=2, sort_keys=True) + "\n").encode())
    print(f"{TAG} image and isolation probes: PASS")


if __name__ == "__main__":
    main()
