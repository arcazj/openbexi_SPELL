"""Generate and verify the Candidate A protobuf artifacts deterministically."""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

from google.protobuf import descriptor_pb2
from grpc_tools import protoc


ROOT = Path(__file__).resolve().parents[1]
PROTO_ROOT = ROOT / "contracts"
PROTO_RELATIVE = Path("spell/driver/v1/driver.proto")
PYTHON_RELATIVE = Path("spell/driver/v1/driver_pb2.py")
GRPC_RELATIVE = Path("spell/driver/v1/driver_pb2_grpc.py")
PYI_RELATIVE = Path("spell/driver/v1/driver_pb2.pyi")
DESCRIPTOR_RELATIVE = Path("contracts/spell_driver_v1.pb")
EXPECTED_SERVICE = "spell.driver.v1.DriverInfrastructureService"
EXPECTED_METHODS = (
    "Handshake",
    "Health",
    "OpenContext",
    "CloseContext",
    "AttachExecution",
    "DetachExecution",
    "CancelLifecycleOperation",
    "DrainHost",
    "GetOperation",
)


def _generate(output_root: Path) -> tuple[Path, ...]:
    descriptor = output_root / DESCRIPTOR_RELATIVE
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    result = protoc.main(
        [
            "grpc_tools.protoc",
            f"--proto_path={PROTO_ROOT}",
            f"--python_out={output_root}",
            f"--pyi_out={output_root}",
            f"--grpc_python_out={output_root}",
            f"--descriptor_set_out={descriptor}",
            "--include_source_info",
            PROTO_RELATIVE.as_posix(),
        ]
    )
    if result != 0:
        raise RuntimeError(f"protoc failed with exit code {result}")
    outputs = (
        output_root / PYTHON_RELATIVE,
        output_root / GRPC_RELATIVE,
        output_root / PYI_RELATIVE,
        descriptor,
    )
    for output in outputs:
        if not output.is_file():
            raise RuntimeError(f"protoc did not create {output.relative_to(output_root)}")
    _validate_descriptor(descriptor)
    return outputs


def _validate_descriptor(path: Path) -> None:
    descriptor_set = descriptor_pb2.FileDescriptorSet.FromString(path.read_bytes())
    services = []
    for file_descriptor in descriptor_set.file:
        package = file_descriptor.package
        for service in file_descriptor.service:
            qualified = f"{package}.{service.name}" if package else service.name
            services.append((qualified, tuple(method.name for method in service.method)))
        for message in file_descriptor.message_type:
            for field in message.field:
                if field.type_name in {
                    ".google.protobuf.Any",
                    ".google.protobuf.Struct",
                    ".google.protobuf.Value",
                }:
                    raise RuntimeError(f"untyped protobuf escape hatch: {field.type_name}")
                if field.type == field.TYPE_MESSAGE and field.type_name.endswith("Entry"):
                    target = next(
                        (
                            candidate
                            for candidate in file_descriptor.message_type
                            if f".{package}.{candidate.name}" == field.type_name
                        ),
                        None,
                    )
                    if target is not None and target.options.map_entry:
                        raise RuntimeError("protobuf map fields are outside Candidate A")
    if services != [(EXPECTED_SERVICE, EXPECTED_METHODS)]:
        raise RuntimeError(f"descriptor RPC surface differs: {services!r}")


def _compare(first: tuple[Path, ...], second: tuple[Path, ...]) -> None:
    for left, right in zip(first, second):
        if not filecmp.cmp(left, right, shallow=False):
            raise RuntimeError(f"non-deterministic output: {left.name}")


def _committed_path(generated: Path, staging_root: Path) -> Path:
    return ROOT / generated.relative_to(staging_root)


def _check_or_write(outputs: tuple[Path, ...], staging_root: Path, write: bool) -> None:
    changed = []
    for generated in outputs:
        committed = _committed_path(generated, staging_root)
        if not committed.is_file() or committed.read_bytes() != generated.read_bytes():
            changed.append(committed)
    if changed and not write:
        names = ", ".join(path.relative_to(ROOT).as_posix() for path in changed)
        raise RuntimeError(f"generated driver contract artifacts are stale: {names}")
    if write:
        for generated in outputs:
            committed = _committed_path(generated, staging_root)
            committed.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(generated, committed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="spell-driver-contract-a-") as first_dir:
        with tempfile.TemporaryDirectory(prefix="spell-driver-contract-b-") as second_dir:
            first_root = Path(first_dir)
            second_root = Path(second_dir)
            first = _generate(first_root)
            second = _generate(second_root)
            _compare(first, second)
            _check_or_write(first, first_root, args.write)
            digest = hashlib.sha256((first_root / DESCRIPTOR_RELATIVE).read_bytes()).hexdigest()
            print(
                f"service={EXPECTED_SERVICE} methods={len(EXPECTED_METHODS)} "
                f"descriptor_sha256={digest} deterministic=true"
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
