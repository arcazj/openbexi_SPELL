"""Deterministically generate the additive, typed DSS RPC contract."""
from __future__ import annotations

import argparse
import tempfile
from pathlib import Path
from grpc_tools import protoc

ROOT = Path(__file__).resolve().parents[1]
RELATIVE = "spell/driver/dss/v1/dss"


def generate(directory: Path) -> dict[str, bytes]:
    result = protoc.main([
        "grpc_tools.protoc", f"--proto_path={ROOT / 'contracts'}",
        f"--python_out={directory}", f"--pyi_out={directory}",
        f"--grpc_python_out={directory}", f"{RELATIVE}.proto",
    ])
    if result:
        raise RuntimeError("DSS protobuf generation failed")
    return {f"{RELATIVE}{suffix}": (directory / f"{RELATIVE}{suffix}").read_bytes()
            for suffix in ("_pb2.py", "_pb2.pyi", "_pb2_grpc.py")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        first, second = generate(Path(a)), generate(Path(b))
        if first != second:
            raise RuntimeError("DSS protobuf generation is not reproducible")
        for name, content in first.items():
            path = ROOT / name
            if args.write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            elif not path.is_file() or path.read_bytes() != content:
                raise RuntimeError(f"DSS generated contract is stale: {name}")


if __name__ == "__main__":
    main()
