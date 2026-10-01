"""Inspect the exact v0.12 images and running local isolation boundaries."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess


def call(*args):
    return subprocess.check_output(["docker", *args], stderr=subprocess.PIPE).decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    images = {}
    for name in ("backend", "driver", "frontend", "proxy"):
        image = f"openbexi-spell-{name}:v0.12.0"
        identity = json.loads(call("image", "inspect", image))[0]
        assert identity["Config"]["User"] not in ("", "root", "0", "0:0")
        root = "/app" if name in {"backend", "driver"} else "/src/frontend" if name == "frontend" else "/usr/share/nginx/html"
        files = call("run", "--rm", "--network", "none", "--entrypoint", "find", image, root, "-type", "f").splitlines()
        forbidden = [value for value in files if Path(value).suffix.lower() in {".pdf", ".zip", ".pyc", ".pyo", ".key", ".pem"}
                     or Path(value).name in {".env", "credentials.json", "secrets.json"}]
        assert not forbidden, (name, forbidden)
        row = {"image_id": identity["Id"], "user": identity["Config"]["User"], "product_files": len(files), "forbidden_files": []}
        if name in {"backend", "driver"}:
            code = ("import hashlib,json,pathlib,zlib; p=pathlib.Path('/usr/lib/x86_64-linux-gnu/libz.so.1'); "
                    "print(json.dumps({'runtime_version':zlib.ZLIB_RUNTIME_VERSION,'library_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),"
                    "'upstream_commit':pathlib.Path('/usr/local/share/openbexi/zlib-source-commit').read_text().strip()}))")
            row["zlib"] = json.loads(call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", code))
            assert row["zlib"]["upstream_commit"] == "df84af25dc1942490e1d1c899a07619152a46148"
            assert row["zlib"]["runtime_version"] == "1.3.2.1-motley"
        if name == "backend":
            version = call("run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", "from backend.version import PRODUCT_VERSION; print(PRODUCT_VERSION)").strip()
            assert version == "0.12.0"
            row["product_version"] = version
        images[name] = row
    services = {}
    for service in ("backend", "postgres", "spell-driver", "bundle-builder-a", "bundle-builder-b", "proxy"):
        ids = call("ps", "--filter", "label=com.docker.compose.project=spellv012release", "--filter", "label=com.docker.compose.service=" + service, "--format", "{{.ID}}").splitlines()
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
    print("v0.12 image and isolation probes: PASS")


if __name__ == "__main__":
    main()
