"""Exact-binary applicability proof for CVE-2026-95619 on Debian amd64.

Upstream 59d235ffa5a69231eb42e5290d52dc8c90d28b7a explicitly excludes
the POSIX implementation: its size argument is not rounded. GCC 14 backport
200183d4ab5d57575f3dfebc6af3baf649910b9e leaves that implementation unchanged.
The pinned library was independently disassembled: aligned new passes the
original nonzero size to posix_memalign, without the vulnerable addition.
This review does not cover other builds, architectures, or advisories.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess

ADVISORY = "CVE-2026-95619"
UPSTREAM = "59d235ffa5a69231eb42e5290d52dc8c90d28b7a"
BACKPORT = "200183d4ab5d57575f3dfebc6af3baf649910b9e"
PURL = "pkg:deb/debian/gcc-14@14.2.0-19?os_distro=trixie&os_name=debian&os_version=13"
LIBRARY = "/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.33"
LIBRARY_SHA256 = "972bb2a18b71140dab0240f8a1f68ab3fb1d56bcd4c4f824a91b70888faf5a00"
LOCATIONS = {"/usr/lib/x86_64-linux-gnu/libgcc_s.so.1", LIBRARY,
             "/usr/share/doc/gcc-14-base/copyright", "/var/lib/dpkg/status"}
SYMBOL = "_ZnwmSt11align_val_t"
FUNCTIONS = {
    SYMBOL: (736288, 125, "aae58ca46ab1f3cc33a8aa49e5f8217d10a9826636943a14dbb35154bb25b8c7"),
    "_ZnamSt11align_val_t": (736448, 9, "d282b8f38a864e3b975b4c76b31c6942f1e8590218e771c174f07121e217f2e4"),
    "_ZnwmSt11align_val_tRKSt9nothrow_t": (736416, 30, "5a9487e99d3385ada40afc9245d882ce73c0595ec9c4a321ade850c7b3a19a0a"),
    "_ZnamSt11align_val_tRKSt9nothrow_t": (736464, 30, "fb31e8d50222f4250cd2fec85a07f3ac4204f1ed65f4acfb05e8c75fe15a9f09"),
}
MAX_SIZE = (1 << 64) - 1
BOUNDARIES = ((MAX_SIZE - 8, 32), (MAX_SIZE, 8), (MAX_SIZE, 32),
              (MAX_SIZE, 1024), (MAX_SIZE, 65536), (MAX_SIZE - 1, 16),
              (MAX_SIZE - 1025, 1024), (MAX_SIZE - 1024, 1024),
              (MAX_SIZE - 65536, 65536))
CONTROLS = ((1, 8), (33, 32), (1024, 64))


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def inspect_binary(data: bytes) -> dict:
    """Resolve the actual ELF call and relocation, with no disassembler dependency."""
    require(hashlib.sha256(data).hexdigest() == LIBRARY_SHA256, "unreviewed libstdc++ binary")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    require(header[0][:7] == b"\x7fELF\x02\x01\x01" and header[2] == 62,
            "unreviewed ELF architecture")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, header[6] + i * header[11])
                for i in range(header[12])]
    def content(section):
        return data[section[4]:section[4] + section[5]]
    def name(table, offset):
        return table[offset:table.index(b"\0", offset)].decode("ascii")
    names = content(sections[header[13]])
    by_name = {name(names, section[0]): section for section in sections}
    dynamic = by_name[".dynsym"]
    symbol_names = content(sections[dynamic[6]])
    symbols = []
    for offset in range(dynamic[4], dynamic[4] + dynamic[5], dynamic[9]):
        key, _, _, section, address, size = struct.unpack_from("<IBBHQQ", data, offset)
        symbols.append((name(symbol_names, key), address, size, section))
    def at(address, size):
        matches = [s for s in sections if s[1] == 1 and s[3] <= address and address + size <= s[3] + s[5]]
        require(len(matches) == 1, "ambiguous ELF code location")
        section = matches[0]
        offset = section[4] + address - section[3]
        return data[offset:offset + size]
    observed = {}
    for symbol, address, size, section in symbols:
        if symbol in FUNCTIONS:
            code = at(address, size)
            observed[symbol] = (address, size, hashlib.sha256(code).hexdigest())
    require(observed == FUNCTIONS, "unreviewed aligned allocation functions")
    # Reviewed instruction at aligned-new+0x61: call 0x9d650.
    call_address = FUNCTIONS[SYMBOL][0] + 0x61
    call = at(call_address, 5)
    require(call[0] == 0xE8, "missing direct allocator call")
    target = call_address + 5 + struct.unpack_from("<i", call, 1)[0]
    require(target == 0x9D650, "unreviewed allocator PLT target")
    stub = at(target, 6)
    require(stub[:2] == b"\xff\x25", "unreviewed allocator PLT instruction")
    got = target + 6 + struct.unpack_from("<i", stub, 2)[0]
    relocations = []
    for section in sections:
        if section[1] == 4 and section[6] == sections.index(dynamic):
            for offset in range(section[4], section[4] + section[5], section[9]):
                address, info, addend = struct.unpack_from("<QQq", data, offset)
                if address == got:
                    relocations.append((symbols[info >> 32][0], info & 0xFFFFFFFF, addend))
    require(got == 0x25F310 and relocations == [("posix_memalign", 7, 0)],
            "aligned new does not resolve to reviewed POSIX allocator")
    require(not any(s[0] == "aligned_alloc" for s in symbols), "unreviewed C11 allocator import")
    return {"format": "ELF64_LSB_X86_64", "functions": {k: list(v) for k, v in observed.items()},
            "call_address": call_address, "plt_address": target, "got_address": got,
            "allocator": "posix_memalign", "relocation_type": "R_X86_64_JUMP_SLOT",
            "c11_aligned_alloc_import": False}


def expected_evidence() -> dict:
    return {"schema": "gcc-aligned-new-applicability/1", "architecture": "x86_64",
            "package": "libstdc++6:amd64", "version": "14.2.0-19", "library": LIBRARY,
            "library_sha256": LIBRARY_SHA256, "loader_overrides": {},
            "binary": {"format": "ELF64_LSB_X86_64", "functions": {k: list(v) for k, v in FUNCTIONS.items()},
                "call_address": 736385, "plt_address": 0x9D650, "got_address": 0x25F310,
                "allocator": "posix_memalign", "relocation_type": "R_X86_64_JUMP_SLOT",
                "c11_aligned_alloc_import": False},
            "loaded_code_matches_file": True,
            "overflow_cases": [{"size": size, "alignment": align, "scalar_null": True, "array_null": True}
                               for size, align in BOUNDARIES],
            "controls": [{"size": size, "alignment": align, "scalar_aligned_write_free": True,
                          "array_aligned_write_free": True} for size, align in CONTROLS]}


def validate_evidence(evidence: dict) -> None:
    require(_canonical(evidence) == _canonical(expected_evidence()), "unreviewed aligned-new applicability evidence")


def inspect_runtime() -> dict:
    path = Path("/usr/lib/x86_64-linux-gnu/libstdc++.so.6").resolve()
    require(str(path) == LIBRARY, "unreviewed libstdc++ path")
    data = path.read_bytes()
    evidence = {"schema": "gcc-aligned-new-applicability/1", "architecture": platform.machine(),
        "package": "libstdc++6:amd64", "version": subprocess.check_output(
            ["dpkg-query", "-W", "-f=${Version}", "libstdc++6:amd64"], text=True).strip(),
        "library": str(path), "library_sha256": hashlib.sha256(data).hexdigest(),
        "loader_overrides": {k: os.environ[k] for k in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH") if os.environ.get(k)},
        "binary": inspect_binary(data)}
    require(evidence["loader_overrides"] == {}, "unreviewed dynamic loader override")
    library = ctypes.CDLL(str(path))
    loaded = {symbol: hashlib.sha256(ctypes.string_at(ctypes.cast(getattr(library, symbol), ctypes.c_void_p).value,
                                                     values[1])).hexdigest() for symbol, values in FUNCTIONS.items()}
    evidence["loaded_code_matches_file"] = all(loaded[k] == v[2] for k, v in FUNCTIONS.items())
    require(evidence["loaded_code_matches_file"], "loaded aligned-new code differs from reviewed ELF")
    nothrow = ctypes.addressof(ctypes.c_char.in_dll(library, "_ZSt7nothrow"))
    evidence["overflow_cases"] = [{"size": s, "alignment": a} for s, a in BOUNDARIES]
    evidence["controls"] = [{"size": s, "alignment": a} for s, a in CONTROLS]
    for label, new_name, delete_name in (("scalar", "_Znwm", "_ZdlPv"), ("array", "_Znam", "_ZdaPv")):
        allocate = getattr(library, new_name + "St11align_val_tRKSt9nothrow_t")
        allocate.argtypes = [ctypes.c_size_t, ctypes.c_size_t, ctypes.c_void_p]
        allocate.restype = ctypes.c_void_p
        release = getattr(library, delete_name + "St11align_val_t")
        release.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        release.restype = None
        for row in evidence["overflow_cases"]:
            pointer = allocate(row["size"], row["alignment"], nothrow)
            row[label + "_null"] = pointer is None
            if pointer is not None:
                release(pointer, row["alignment"])
        for row in evidence["controls"]:
            pointer = allocate(row["size"], row["alignment"], nothrow)
            valid = pointer is not None and pointer % row["alignment"] == 0
            if pointer is not None:
                ctypes.memset(pointer, 0x5A, row["size"])
                valid = valid and ctypes.string_at(pointer, row["size"]) == b"\x5a" * row["size"]
                release(pointer, row["alignment"])
            row[label + "_aligned_write_free"] = valid
    validate_evidence(evidence)
    return evidence


def resolve_rule(rule: dict, results: list[dict], probe: dict) -> dict:
    require(rule["id"] == ADVISORY, "unreviewed aligned-new advisory")
    require(rule["properties"]["purls"] == [PURL], "unreviewed aligned-new affected package")
    require(len(results) == 1 and results[0]["ruleId"] == ADVISORY, "unreviewed aligned-new finding multiplicity")
    locations = [p["physicalLocation"]["artifactLocation"]["uri"] for p in results[0]["locations"]]
    require(len(locations) == len(LOCATIONS) and set(locations) == LOCATIONS, "unreviewed aligned-new affected files")
    evidence = probe["gcc_aligned_new_applicability"]
    validate_evidence(evidence)
    inventory = probe["gcc_header_applicability"]
    require(inventory["packages"]["libstdc++6:amd64"] == evidence["version"] and
            inventory["files"][LIBRARY] == LIBRARY_SHA256, "aligned-new proof differs from package inventory")
    return {"advisory": ADVISORY, "status": "NOT_AFFECTED", "justification": "vulnerable_code_not_present",
            "upstream_fix": UPSTREAM, "gcc14_backport": BACKPORT, "affected_package": PURL,
            "reviewed_library_sha256": LIBRARY_SHA256,
            "evidence_sha256": hashlib.sha256(_canonical(evidence).encode()).hexdigest()}


if __name__ == "__main__":
    print(json.dumps(inspect_runtime(), sort_keys=True))
