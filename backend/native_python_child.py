"""Trusted Linux launcher: enter the immutable jail, drop identity, then exec CPython."""
from __future__ import annotations

import os
import re
import resource
import sys


def main() -> None:
    if os.getuid() != 0 or len(sys.argv) < 5:
        raise RuntimeError("Python isolation launcher requires its privileged service identity")
    job, filename = sys.argv[1:3]
    if re.fullmatch(r"[0-9a-f]{32}", job) is None or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.py", filename) is None:
        raise RuntimeError("Python isolation launcher arguments are invalid")
    # Standard-library compression plus retained thread arenas need address space;
    # the service's separate cgroup still bounds resident memory to 512 MiB.
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (30, 31))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    os.chroot("/opt/spell-python")
    os.chdir("/tmp/" + job)
    os.setgroups([])
    os.setgid(20000)
    os.setuid(20000)
    if os.getuid() != 20000 or os.geteuid() != 20000:
        raise RuntimeError("Python isolation identity was not dropped")
    ready_fd = int(sys.argv[3])
    os.write(ready_fd, b"ready")
    os.close(ready_fd)
    environment = {"PATH": "/usr/local/bin", "LANG": "C.UTF-8", "TZ": "UTC",
                   "TMPDIR": "/tmp/" + job + "/tmp"}
    debug_fd = int(sys.argv[4])
    os.set_inheritable(debug_fd, True)
    os.execve("/usr/local/bin/python3", ["python3", "-I", "-S", "-B", "-u", "-X", "utf8",
              "/usr/local/lib/spell_python_debug.py", str(debug_fd),
              "/tmp/" + job + "/" + filename, *sys.argv[5:]], environment)


if __name__ == "__main__":
    main()
