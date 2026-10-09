ARG SPELL_PYTHON_BACKEND_IMAGE=openbexi-spell-backend:python-local
FROM ${SPELL_PYTHON_BACKEND_IMAGE}
USER 0:0
# The jail contains CPython, its standard library and patched shared libraries.
# It contains no backend, driver, third-party site packages, or service volumes.
RUN mkdir -p /opt/spell-python/usr/local/bin /opt/spell-python/usr/local/lib \
        /opt/spell-python/lib /opt/spell-python/lib64 /opt/spell-python/usr/lib \
        /opt/spell-python/tmp /opt/spell-python/etc /opt/spell-python/dev \
    && cp -a /usr/local/bin/python3* /opt/spell-python/usr/local/bin/ \
    && cp -a /usr/local/lib/libpython3.13.so* /opt/spell-python/usr/local/lib/ \
    && cp -a /etc/ld.so.cache /opt/spell-python/etc/ \
    && cp -a /lib/. /opt/spell-python/lib/ \
    && cp -a /lib64/. /opt/spell-python/lib64/ \
    && cp -a /usr/lib/. /opt/spell-python/usr/lib/ \
    && python -c "import shutil; shutil.copytree('/usr/local/lib/python3.13','/opt/spell-python/usr/local/lib/python3.13',ignore=shutil.ignore_patterns('site-packages','__pycache__')); open('/opt/spell-python/etc/hosts','w').write('127.0.0.1 localhost\n::1 localhost\n')" \
    && mknod -m 666 /opt/spell-python/dev/null c 1 3
COPY --chmod=444 backend/native_python_debug.py /opt/spell-python/usr/local/lib/spell_python_debug.py
ENTRYPOINT ["python", "-m", "backend.native_python_runner"]
CMD []
