#!/bin/sh
set -eu
# Upstream's CVE-2026-85091 fix, independently hash-bound before compilation.
apt-get update
apt-get install -y --no-install-recommends build-essential
python - <<'PY'
import hashlib, urllib.request
from pathlib import Path
url = 'https://codeload.github.com/madler/zlib/tar.gz/df84af25dc1942490e1d1c899a07619152a46148'
data = urllib.request.urlopen(url, timeout=60).read()
assert hashlib.sha256(data).hexdigest() == '03a76732cfaa124c58b67600699d935d081604385c03aa282f81a101b7536161'
Path('/tmp/zlib.tar.gz').write_bytes(data)
PY
mkdir /tmp/zlib-source /tmp/zlib-package
tar -xzf /tmp/zlib.tar.gz -C /tmp/zlib-source --strip-components=1
cd /tmp/zlib-source
./configure --prefix=/usr
make -j2
make test
mkdir -p /tmp/zlib-package/DEBIAN /tmp/zlib-package/usr/lib/x86_64-linux-gnu /tmp/zlib-package/usr/share/doc/zlib1g
cp libz.so.1.3.2.1-motley /tmp/zlib-package/usr/lib/x86_64-linux-gnu/
ln -s libz.so.1.3.2.1-motley /tmp/zlib-package/usr/lib/x86_64-linux-gnu/libz.so.1
cp LICENSE /tmp/zlib-package/usr/share/doc/zlib1g/copyright
printf '%s\n' 'df84af25dc1942490e1d1c899a07619152a46148' > /tmp/zlib-package/usr/share/doc/zlib1g/openbexi-upstream-commit
cat > /tmp/zlib-package/DEBIAN/control <<'EOF'
Package: zlib1g
Version: 1:1.3.2.1+git.df84af2-0openbexi1
Architecture: amd64
Maintainer: OpenBEXI SPELL contributors
Depends: libc6 (>= 2.14)
Section: libs
Priority: optional
Description: zlib with upstream CVE-2026-85091 correction
 Built from hash-pinned upstream commit df84af25dc1942490e1d1c899a07619152a46148.
EOF
dpkg-deb --root-owner-group --build /tmp/zlib-package /tmp/zlib-fixed.deb
