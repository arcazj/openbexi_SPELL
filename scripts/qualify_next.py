"""Canonical, source-bound v0.13-v0.19 qualification producer (Windows host, Linux Docker)."""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET

from scripts.release_next import ROOT, VERSION, MINOR, TAG, POLICY, PYTHON_RELEASE, RELEASE_KEY, PROJECT, fingerprint, git, require, write_json, verify_candidate, policy
from scripts.gcc_header_applicability import resolve

OUT = ROOT / f".qualification/v{RELEASE_KEY}/final"
QUALIFIER = "openbexi-spell-qualification:next"
IMAGE_NAMES = ("backend", "driver", "frontend", "proxy") + (("dss", "kafka") if MINOR >= 19 else ()) + (("python",) if PYTHON_RELEASE else ())
IMAGES = {name: f"openbexi-spell-{name}:{TAG}" for name in IMAGE_NAMES}
COMPOSE_TESTS = ["backend/tests/test_driver_isolation.py::" + name for name in (
    "test_created_compose_driver_has_runtime_isolation_controls",
    "test_live_bundle_builders_are_networkless_independent_and_reproducible",
    "test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
)] + (["backend/tests/test_proxy_dns_recovery_v19.py::test_actual_nginx_recovers_backend_and_dss_dns_replacement_without_restart"] if MINOR >= 19 else [])
DOC_TESTS = ["scripts/tests/test_markdown_preview_v09.py", "scripts/tests/test_documentation_tree_layout.py"]
TOOL_TESTS = ["scripts/tests/test_release_v12.py", "scripts/tests/test_release_next.py", "scripts/tests/test_spell_auditor_tool.py"]
if MINOR >= 18:
    TOOL_TESTS.append("scripts/tests/test_gcc_aligned_new_applicability.py")
if MINOR >= 19:
    TOOL_TESTS += ["scripts/tests/test_dss_delivery.py", "scripts/tests/test_dss_release_gate.py",
                   "scripts/tests/test_seed_dss_v19.py", "scripts/tests/test_dss_continuation.py"]
if PYTHON_RELEASE:
    TOOL_TESTS.append("scripts/tests/test_release_v191.py")


MODULE_PYTEST = "from scripts.qualify_next import run_module_pytest; import json,sys; run_module_pytest(sys.argv[1],json.loads(sys.argv[2]))"
MODULE_COLLECTION = r'''import json,sys,pytest
from pathlib import Path
from _pytest.junitxml import mangle_test_address
class Catalog:
 def pytest_collection_finish(self,session):
  rows=[]
  for item in session.items:
   names=mangle_test_address(item.nodeid)
   rows.append({'identity':'.'.join(names[:-1])+'::'+names[-1],'file':item.nodeid.split('::',1)[0]})
  Path(sys.argv[1]).write_text(json.dumps(rows))
raise SystemExit(pytest.main([*json.loads(sys.argv[2]),'--collect-only','-q','-p','no:cacheprovider'],plugins=[Catalog()]))
'''


def partition_module_pytest(catalog, expected):
    """Partition the actual collection without dropping, renaming or repeating cases."""
    require(type(catalog) is list and catalog and type(expected) is list and expected
            and len(expected) == len(set(expected)), 'Invalid module pytest inventory')
    groups, identities = {}, []
    for row in catalog:
        require(type(row) is dict and set(row) == {'identity', 'file'}
                and type(row['identity']) is str and type(row['file']) is str, 'Invalid module pytest row')
        name = row['file']
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and str(path) == name
                and name.startswith(('backend/tests/', 'driver_host/tests/')) and name.endswith('.py')
                and '\\' not in name and not any(char in name for char in '\r\n\0'), 'Unsafe pytest module')
        module = name[:-3].replace('/', '.')
        require(row['identity'].startswith((module + '::', module + '.')), 'Pytest module identity differs')
        identities.append(row['identity'])
        groups.setdefault(name, []).append(row['identity'])
    require(len(identities) == len(set(identities)) and set(identities) == set(expected),
            'Module pytest collection differs from the frozen inventory')
    return list(groups.items())


def append_module_pytest_report(aggregate, name, raw, expected, command, returncode, log):
    """Retain raw child evidence and append its unchanged testcase elements."""
    require(aggregate.tag == 'testsuites' and type(raw) is bytes and type(log) is bytes
            and 0 < len(raw) <= 32_000_000 and len(log) <= 32_000_000
            and type(returncode) is int and type(command) is list and len(command) == 9
            and command[:4] == [sys.executable, '-m', 'pytest', name]
            and command[4:8] == ['-q', '-p', 'no:cacheprovider', '--tb=short']
            and command[8].startswith('--junitxml=/tmp/'), 'Pytest module command or bytes differ')
    metadata = next((row for row in aggregate if row.get('name') == 'spell.pytest-modules'), None)
    if metadata is None:
        metadata = ET.SubElement(aggregate, 'testsuite', name='spell.pytest-modules', tests='0',
                                 failures='0', errors='0', skipped='0', time='0')
        ET.SubElement(metadata, 'properties')
    properties = metadata.find('properties')
    require(not any(row.get('name') == name for row in properties), 'Repeated pytest module')
    record = {'module': name, 'command': command, 'returncode': returncode, 'expected_identities': expected,
              'report_sha256': hashlib.sha256(raw).hexdigest(), 'report_base64': base64.b64encode(raw).decode('ascii'),
              'log_sha256': hashlib.sha256(log).hexdigest(), 'log_base64': base64.b64encode(log).decode('ascii')}
    ET.SubElement(properties, 'property', name=name, value=json.dumps(record, sort_keys=True))
    document = ET.fromstring(raw)
    require(document.tag == 'testsuites' and document.findall('testsuite'), 'Invalid pytest module XML')
    aggregate.extend(document.findall('testsuite'))
    cases = document.findall('.//testcase')
    actual = [row.get('classname', '') + '::' + row.get('name', '') for row in cases]
    require(len(actual) == len(set(actual)) and set(actual) <= set(expected), 'Unexpected pytest module cases')
    if returncode == 0:
        require(set(actual) == set(expected)
                and not any(child.tag in {'failure', 'error'} for row in cases for child in row),
                'Successful pytest module has missing or failed cases')
    return record


def run_module_pytest(gate, tests, *, expected=None):
    """Run each collected database-test module once in a fresh pytest process."""
    require(gate in {'sqlite', 'postgresql'}, 'Module isolation is limited to database gates')
    frozen = policy()['gates'][gate]
    identities = frozen['identities'] if expected is None else expected
    output = Path('/evidence') / (gate + '.xml')
    aggregate = ET.Element('testsuites')
    with tempfile.TemporaryDirectory(prefix='spell-pytest-modules-', dir='/tmp') as staging:
        staging = Path(staging)
        catalog_path = staging / 'catalog.json'
        collected = subprocess.run([sys.executable, '-c', MODULE_COLLECTION, str(catalog_path), json.dumps(tests)],
                                   capture_output=True)
        sys.stdout.buffer.write(collected.stdout + collected.stderr)
        sys.stdout.buffer.flush()
        require(collected.returncode == 0, 'Module pytest collection failed')
        groups = partition_module_pytest(json.loads(catalog_path.read_bytes()), identities)
        for index, (name, selected) in enumerate(groups):
            report = staging / (str(index) + '.xml')
            command = [sys.executable, '-m', 'pytest', name, '-q', '-p', 'no:cacheprovider', '--tb=short',
                       '--junitxml=' + str(report)]
            print('START pytest module ' + name, flush=True)
            result = subprocess.run(command, capture_output=True)
            log = result.stdout + result.stderr
            sys.stdout.buffer.write(log)
            sys.stdout.buffer.flush()
            require(report.is_file() and not report.is_symlink(), 'Pytest module report is missing or linked')
            try:
                append_module_pytest_report(aggregate, name, report.read_bytes(), selected, command, result.returncode, log)
            finally:
                pending = output.with_suffix('.pending')
                pending.write_bytes(ET.tostring(aggregate, encoding='utf-8', xml_declaration=True))
                pending.replace(output)
            if result.returncode != 0:
                raise SystemExit(result.returncode)
            print('FINISH pytest module ' + name, flush=True)
    if expected is None:
        from scripts.release_next import junit
        actual = junit(output)
        require(all(actual[key] == frozen[key] for key in ('tests', 'identities', 'skipped')),
                'Combined pytest report differs from the frozen gate')


SOURCE_AUDIT = r'''import hashlib,json,stat,sys
from pathlib import Path,PurePosixPath
root=Path(sys.argv[1]);pin=sys.argv[2]
raw=(root/'.spell-source-snapshot.json').read_bytes()
if hashlib.sha256(raw).hexdigest()!=pin:raise SystemExit('source manifest hash differs')
manifest=json.loads(raw);names=set(manifest['files'])
for name,row in manifest['files'].items():
 p=PurePosixPath(name)
 if p.is_absolute() or '..' in p.parts or str(p)!=name:raise SystemExit('unsafe source path')
 file=root/name
 if file.is_symlink() or not file.is_file():raise SystemExit('missing or linked source file: '+name)
 data=file.read_bytes()
 if len(data)!=row['bytes'] or hashlib.sha256(data).hexdigest()!=row['sha256']:raise SystemExit('source bytes differ: '+name)
 if stat.S_IMODE(file.stat().st_mode)!=int(row['mode'],8):raise SystemExit('source mode differs: '+name)
actual=set()
for file in root.rglob('*'):
 if file.is_symlink():raise SystemExit('linked snapshot entry')
 if file.is_file():actual.add(file.relative_to(root).as_posix())
if actual!=names|{'.spell-source-snapshot.json'}:raise SystemExit('unexpected source files')
print(json.dumps({'decision':'PASS','source_commit':manifest['source_commit'],'manifest_sha256':pin,'files':len(names)}))
'''


def source_snapshot_input(root):
    """Bind every tracked regular disk file and its Git mode before Linux copying."""
    require(not subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain']),
            'Linux source snapshot requires clean committed source')
    source = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD']).decode().strip()
    rows = subprocess.check_output(['git', '-C', str(root), 'ls-files', '--stage', '-z']).split(b'\0')
    files, payloads = {}, {}
    for record in filter(None, rows):
        header, encoded = record.split(b'\t', 1)
        mode, blob, stage = header.decode().split()
        name = encoded.decode('utf-8')
        relative = PurePosixPath(name)
        require(stage == '0' and mode in {'100644', '100755'} and name not in files
                and not relative.is_absolute() and '..' not in relative.parts and str(relative) == name
                and not any(value in name for value in ('\r', '\n', '\0')),
                'Unsafe tracked Linux source entry')
        path = root / name
        require(path.is_file() and not path.is_symlink(), 'Missing or linked source file: ' + name)
        data = path.read_bytes()
        require(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() == blob,
                'Raw source bytes differ from the committed Git blob: ' + name)
        files[name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'mode': mode[-3:]}
        payloads[name] = data
    require(files and sum(map(len, payloads.values())) <= 1_000_000_000, 'Linux source snapshot size differs')
    require((root / '.git').is_dir(), 'Canonical qualification requires a standalone Git checkout')
    value = {'schema_version': 'spell.qualification-linux-source/1', 'source_commit': source, 'files': files}
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    return value, raw, payloads


def linux_source_snapshot(*, gate, snapshot=None):
    """Stage once per source identity, then audit a read-only Linux volume."""
    if snapshot is None:
        manifest, raw, payloads = source_snapshot_input(ROOT)
        pin = hashlib.sha256(raw).hexdigest()
        volume = f'spellv0{MINOR}-qualified-source-' + manifest['source_commit'][:12] + '-' + pin[:32]
        snapshot = {'source_commit': manifest['source_commit'], 'manifest_sha256': pin,
                    'files': len(manifest['files']), 'bytes': sum(map(len, payloads.values())),
                    'volume': volume, 'manifest': manifest, 'audits': []}
    else:
        raw = (json.dumps(snapshot['manifest'], sort_keys=True, indent=2) + '\n').encode()
        pin, volume, payloads = snapshot['manifest_sha256'], snapshot['volume'], None
    commands = []
    def call(*args, timeout=30, input=None):
        began = time.monotonic()
        result = subprocess.run(['docker', *map(str, args)], input=input, capture_output=True, timeout=timeout)
        commands.append({'command': ['docker', *[str(value).replace(str(ROOT), '<repository>') for value in args]],
                         'returncode': result.returncode, 'seconds': round(time.monotonic()-began, 3)})
        require(result.returncode == 0, 'Linux source staging command failed: ' + str(args[0]))
        return result.stdout
    names = call('volume', 'ls', '--filter', 'name=^'+volume+'$', '--format', '{{.Name}}').decode().splitlines()
    require(names in ([], [volume]), 'Linux source volume identity differs')
    new = not names
    if new:
        require(payloads is not None, 'Audited source volume disappeared during qualification')
        call('volume', 'create', '--label', 'openbexi.qualification.source='+snapshot['source_commit'],
             '--label', 'openbexi.qualification.manifest='+pin, volume)
    labels = json.loads(call('volume', 'inspect', volume))[0]['Labels']
    require(labels.get('openbexi.qualification.source') == snapshot['source_commit']
            and labels.get('openbexi.qualification.manifest') == pin, 'Foreign Linux source volume')
    marker = uuid.uuid4().hex
    name = f'spell-v{MINOR}-source-audit-'+marker
    mode = 'rw' if new else 'ro'
    cid = call('create', '--name', name, '--label', 'openbexi.qualification.source-audit='+marker,
               '--network', 'none', '-v', volume+':/snapshot:'+mode, '--entrypoint', 'python',
               QUALIFIER, '-c', SOURCE_AUDIT, '/snapshot', pin).decode().strip()
    require(re.fullmatch('[0-9a-f]{64}', cid), 'Source audit container ID differs')
    def owned():
        record = json.loads(call('inspect', cid))[0]
        require(record['Id'] == cid and record['Name'] == '/'+name
                and record['Config']['Labels'].get('openbexi.qualification.source-audit') == marker,
                'Source audit container ownership differs')
        return record
    try:
        owned()
        if new:
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w') as tar:
                git_directory = tarfile.TarInfo('.git')
                git_directory.type, git_directory.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(git_directory)
                for filename, data in sorted({**payloads, '.spell-source-snapshot.json': raw}.items()):
                    item = tarfile.TarInfo(filename)
                    item.size, item.mtime = len(data), 0
                    item.mode = int(manifest['files'][filename]['mode'], 8) if filename in payloads else 0o644
                    tar.addfile(item, io.BytesIO(data))
            call('cp', '-', cid+':/snapshot', input=archive.getvalue(), timeout=120)
            archive.close()
        call('start', cid, timeout=20)
        exit_code = call('wait', cid, timeout=120).decode().strip()
        record = owned()
        require(exit_code == '0' and record['State']['ExitCode'] == 0 and not record['State']['Running'],
                'Linux source audit failed')
        audit = json.loads(call('logs', cid))
        require(audit == {'decision': 'PASS', 'source_commit': snapshot['source_commit'],
                         'manifest_sha256': pin, 'files': snapshot['files']}, 'Linux source audit receipt differs')
        snapshot['audits'].append({'gate': gate, 'receipt': audit, 'commands': commands})
        write_json(OUT / (gate+'.source-snapshot.json'), snapshot)
        return snapshot
    finally:
        state = owned()['State']
        if not state['Running'] and state['Pid'] == 0:
            call('rm', cid, timeout=20)
        if snapshot['audits']:
            write_json(OUT / (gate+'.source-snapshot.json'), snapshot)


PYTEST_GATES = frozenset({'candidate', 'sqlite', 'postgresql', 'compose', 'documentation', 'tooling'})
PYTEST_REPORT_AUDIT = r'''import hashlib,json,stat,sys
from pathlib import Path
root=Path('/snapshot');expected=sys.argv[1]
entries=list(root.iterdir())
if len(entries)!=1 or entries[0].name!=expected:raise SystemExit('pytest evidence inventory differs')
file=entries[0]
if file.is_symlink() or not stat.S_ISREG(file.stat().st_mode):raise SystemExit('pytest evidence is not a regular file')
data=file.read_bytes()
if not 0<len(data)<=32_000_000:raise SystemExit('pytest evidence size differs')
print(json.dumps({'name':expected,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mode':format(stat.S_IMODE(file.stat().st_mode),'03o')}))
'''


def require_pytest_evidence_owner(record, evidence):
    labels = record.get('Labels') or {}
    require(record.get('Name') == evidence['volume']
            and labels.get('openbexi.qualification.evidence') == evidence['marker']
            and labels.get('openbexi.qualification.source') == evidence['source_commit'],
            'Foreign pytest evidence volume')


def validate_pytest_report_copy(expected, receipt, data):
    require(expected in {gate+'.xml' for gate in PYTEST_GATES}
            and receipt.get('name') == expected, 'Pytest report name differs')
    require(type(receipt.get('bytes')) is int and 0 < receipt['bytes'] <= 32_000_000
            and len(data) == receipt['bytes'] and receipt.get('mode') == '644',
            'Pytest report size or mode differs')
    require(receipt.get('sha256') == hashlib.sha256(data).hexdigest(),
            'Copied pytest report bytes differ from Linux evidence')
    try:
        document = ET.fromstring(data)
    except ET.ParseError as error:
        raise ValueError('Copied pytest report is not valid XML') from error
    require(document.tag == 'testsuites' and document.findall('.//testcase'),
            'Copied pytest report has no actual test cases')


def pytest_evidence_command(evidence, *args, timeout=30):
    began = time.monotonic()
    result = subprocess.run(['docker', *map(str, args)], capture_output=True, timeout=timeout)
    def display(value):
        return str(value).replace(str(ROOT), '<repository>').replace(ROOT.as_posix(), '<repository>')
    evidence['commands'].append({'command': ['docker', *map(display, args)], 'returncode': result.returncode,
                                 'seconds': round(time.monotonic()-began, 3)})
    require(result.returncode == 0, 'Pytest evidence operation failed: '+str(args[0]))
    return result.stdout


def create_linux_pytest_evidence(gate, source):
    require(gate in PYTEST_GATES and re.fullmatch('[0-9a-f]{40}', source), 'Pytest evidence identity differs')
    marker = uuid.uuid4().hex
    evidence = {'schema_version': 'spell.qualification-linux-pytest-evidence/1',
                'gate': gate, 'source_commit': source, 'marker': marker,
                'volume': f'spell-v{MINOR}-pytest-evidence-'+marker,
                'report_name': gate+'.xml', 'commands': [], 'reports': []}
    call = lambda *args, **kwargs: pytest_evidence_command(evidence, *args, **kwargs)
    require(not call('volume', 'ls', '--filter', 'name=^'+evidence['volume']+'$', '--format', '{{.Name}}').strip(),
            'Pytest evidence volume already exists')
    call('volume', 'create', '--label', 'openbexi.qualification.evidence='+marker,
         '--label', 'openbexi.qualification.source='+source, evidence['volume'])
    require_pytest_evidence_owner(json.loads(call('volume', 'inspect', evidence['volume']))[0], evidence)
    write_json(OUT/(gate+'.pytest-evidence.json'), evidence)
    return evidence


def require_pytest_reader_owner(row, evidence):
    reader = evidence['reader']
    require(row['Id'] == reader['id'] and row['Name'] == '/'+reader['name']
            and row['Image'] == reader['image_id']
            and row['Config']['Labels'].get('openbexi.qualification.evidence-reader') == reader['marker']
            and row['Config']['Labels'].get('openbexi.qualification.source') == evidence['source_commit']
            and row['HostConfig']['NetworkMode'] == 'none', 'Pytest reader ownership differs')
    mounts = {item['Destination']: item for item in row['Mounts']}
    require(set(mounts) == {'/snapshot', '/source'} and all(
        mounts[path]['Type'] == 'volume' and mounts[path]['Name'] == volume and mounts[path]['RW'] is False
        for path, volume in (('/snapshot', evidence['volume']), ('/source', evidence['source_snapshot']['volume']))),
        'Pytest reader mounts differ')


def start_linux_pytest_reader(evidence, snapshot):
    """Prepare one owned read-only reader before the heavy test writer starts."""
    require(snapshot['source_commit'] == evidence['source_commit'] and len(snapshot['audits']) == 1,
            'Pytest reader source binding differs')
    require('reader' not in evidence, 'Pytest reader already exists')
    call = lambda *args, **kwargs: pytest_evidence_command(evidence, *args, **kwargs)
    require_pytest_evidence_owner(json.loads(call('volume', 'inspect', evidence['volume']))[0], evidence)
    marker = uuid.uuid4().hex
    name = f'spell-v{MINOR}-pytest-evidence-reader-'+marker
    cid = call('create', '--name', name, '--label', 'openbexi.qualification.evidence-reader='+marker,
               '--label', 'openbexi.qualification.source='+evidence['source_commit'], '--network', 'none',
               '-v', evidence['volume']+':/snapshot:ro', '-v', snapshot['volume']+':/source:ro',
               '--entrypoint', 'python', QUALIFIER, '-c', 'import time;time.sleep(7200)').decode().strip()
    require(re.fullmatch('[0-9a-f]{64}', cid), 'Pytest reader container ID differs')
    row = json.loads(call('inspect', cid))[0]
    evidence['reader'] = {'id': cid, 'name': name, 'marker': marker, 'image_id': row['Image']}
    evidence['source_snapshot'] = snapshot
    require_pytest_reader_owner(row, evidence)
    try:
        call('start', cid, timeout=20)
        row = json.loads(call('inspect', cid))[0]
        require_pytest_reader_owner(row, evidence)
        require(row['State']['Running'] and row['State']['Pid'] > 0, 'Pytest reader did not start')
        evidence['reader']['started_before_writer'] = True
    except BaseException:
        close_linux_pytest_reader(evidence)
        raise
    finally:
        write_json(OUT/(evidence['gate']+'.pytest-evidence.json'), evidence)


def close_linux_pytest_reader(evidence):
    call = lambda *args, **kwargs: pytest_evidence_command(evidence, *args, **kwargs)
    row = json.loads(call('inspect', evidence['reader']['id']))[0]
    require_pytest_reader_owner(row, evidence)
    if row['State']['Running']:
        call('stop', '--time', '3', row['Id'], timeout=20)
        row = json.loads(call('inspect', row['Id']))[0]
        require_pytest_reader_owner(row, evidence)
    require(not row['State']['Running'] and row['State']['Pid'] == 0, 'Pytest reader is still running')
    call('rm', row['Id'], timeout=20)
    evidence['reader']['cleanup'] = 'owned_stopped_reader_removed'


def collect_started_linux_pytest_reader(evidence):
    """Audit actual post-run source/report bytes without starting a new container."""
    call = lambda *args, **kwargs: pytest_evidence_command(evidence, *args, **kwargs)
    reader = evidence['reader']
    cid = reader['id']
    try:
        row = json.loads(call('inspect', cid))[0]
        require_pytest_reader_owner(row, evidence)
        require(reader['started_before_writer'] and row['State']['Running'] and row['State']['Pid'] > 0,
                'Prepared pytest reader is not running')
        snapshot = evidence['source_snapshot']
        begin = len(evidence['commands'])
        audit = json.loads(call('exec', cid, 'python', '-c', SOURCE_AUDIT, '/source',
                               snapshot['manifest_sha256'], timeout=120))
        require(audit == {'decision': 'PASS', 'source_commit': snapshot['source_commit'],
                         'manifest_sha256': snapshot['manifest_sha256'], 'files': snapshot['files']},
                'Post-run Linux source audit receipt differs')
        snapshot['audits'].append({'gate': evidence['gate'], 'receipt': audit,
                                  'commands': evidence['commands'][begin:]})
        require(len(snapshot['audits']) == 2, 'Pytest source audit count differs')
        evidence['source_after_verified'] = True
        write_json(OUT/(evidence['gate']+'.source-snapshot.json'), snapshot)
        receipt = json.loads(call('exec', cid, 'python', '-c', PYTEST_REPORT_AUDIT,
                                 evidence['report_name'], timeout=120))
        with tempfile.TemporaryDirectory(prefix='pytest-copy-', dir=OUT) as staging:
            require(Path(staging).resolve().is_relative_to(OUT.resolve())
                    and Path(staging).resolve() != OUT.resolve(), 'Unsafe pytest report copy staging')
            destination = Path(staging)/evidence['report_name']
            call('cp', cid+':/snapshot/'+evidence['report_name'], str(destination), timeout=60)
            require(destination.is_file() and not destination.is_symlink(), 'Copied pytest evidence is not a regular file')
            data = destination.read_bytes()
            validate_pytest_report_copy(evidence['report_name'], receipt, data)
            destination.replace(OUT/evidence['report_name'])
            require((OUT/evidence['report_name']).read_bytes() == data, 'Host pytest report changed during replacement')
        evidence['reports'].append({'linux': receipt, 'host_sha256': hashlib.sha256(data).hexdigest(),
                                    'host_bytes': len(data), 'verified_unchanged': True})
    finally:
        close_linux_pytest_reader(evidence)
        write_json(OUT/(evidence['gate']+'.pytest-evidence.json'), evidence)


def collect_linux_pytest_evidence(evidence):
    """Copy one fresh report after its writer exits; verify Linux bytes before replacing the host file."""
    call = lambda *args, **kwargs: pytest_evidence_command(evidence, *args, **kwargs)
    require(evidence['gate'] in PYTEST_GATES and evidence['report_name'] == evidence['gate']+'.xml',
            'Pytest evidence report identity differs')
    require_pytest_evidence_owner(json.loads(call('volume', 'inspect', evidence['volume']))[0], evidence)
    if 'reader' in evidence:
        return collect_started_linux_pytest_reader(evidence)
    marker = uuid.uuid4().hex
    name = f'spell-v{MINOR}-pytest-evidence-audit-'+marker
    cid = call('create', '--name', name, '--label', 'openbexi.qualification.evidence-audit='+marker,
               '--network', 'none', '-v', evidence['volume']+':/snapshot:ro', '--entrypoint', 'python',
               QUALIFIER, '-c', PYTEST_REPORT_AUDIT, evidence['report_name']).decode().strip()
    require(re.fullmatch('[0-9a-f]{64}', cid), 'Pytest report audit container ID differs')
    def owned():
        row = json.loads(call('inspect', cid))[0]
        require(row['Id'] == cid and row['Name'] == '/'+name
                and row['Config']['Labels'].get('openbexi.qualification.evidence-audit') == marker,
                'Pytest report audit container ownership differs')
        return row
    try:
        owned()
        call('start', cid, timeout=20)
        code = call('wait', cid, timeout=120).decode().strip()
        state = owned()['State']
        require(code == '0' and state['ExitCode'] == 0 and not state['Running'], 'Linux pytest report audit failed')
        receipt = json.loads(call('logs', cid))
        with tempfile.TemporaryDirectory(prefix='pytest-copy-', dir=OUT) as staging:
            require(Path(staging).resolve().is_relative_to(OUT.resolve())
                    and Path(staging).resolve() != OUT.resolve(), 'Unsafe pytest report copy staging')
            destination = Path(staging)/evidence['report_name']
            call('cp', cid+':/snapshot/'+evidence['report_name'], str(destination), timeout=60)
            require(destination.is_file() and not destination.is_symlink(), 'Copied pytest evidence is not a regular file')
            data = destination.read_bytes()
            validate_pytest_report_copy(evidence['report_name'], receipt, data)
            destination.replace(OUT/evidence['report_name'])
            require((OUT/evidence['report_name']).read_bytes() == data, 'Host pytest report changed during replacement')
        evidence['reports'].append({'linux': receipt, 'host_sha256': hashlib.sha256(data).hexdigest(),
                                    'host_bytes': len(data), 'verified_unchanged': True})
    finally:
        state = owned()['State']
        if not state['Running'] and state['Pid'] == 0:
            call('rm', cid, timeout=20)
        write_json(OUT/(evidence['gate']+'.pytest-evidence.json'), evidence)


def close_linux_pytest_evidence(evidence):
    require(evidence['reports'] and all(row['verified_unchanged'] for row in evidence['reports']),
            'Cannot remove unverified pytest evidence')
    row = json.loads(pytest_evidence_command(evidence, 'volume', 'inspect', evidence['volume']))[0]
    require_pytest_evidence_owner(row, evidence)
    pytest_evidence_command(evidence, 'volume', 'rm', evidence['volume'])
    evidence['cleanup'] = 'owned_verified_report_volume_removed'
    write_json(OUT/(evidence['gate']+'.pytest-evidence.json'), evidence)


LINUX_SOURCE = None
LINUX_PYTEST_EVIDENCE = None


def docker_python(*args, network="none", extra=()):
    require(LINUX_SOURCE is not None, "Python qualification requires an audited Linux source snapshot")
    pytest_command = args[:2] == ('-m', 'pytest') or args[:2] == ('-c', MODULE_PYTEST)
    require(not pytest_command or LINUX_PYTEST_EVIDENCE is not None, 'Pytest qualification requires fresh Linux evidence storage')
    evidence_path = LINUX_PYTEST_EVIDENCE['volume'] if pytest_command else OUT.as_posix()
    return ["docker", "run", "--rm", "--network", network,
            "-v", f"{LINUX_SOURCE['volume']}:/workspace:ro",
            "-v", f"{(ROOT / '.git').as_posix()}:/workspace/.git:ro",
            "-v", f"{evidence_path}:/evidence",
            *extra, QUALIFIER, *args]


def compose(*args):
    overlays = ["-f", "compose.yaml", "-f", "compose.procedures.yaml", "-f", "compose.python.yaml"] if PYTHON_RELEASE else []
    return ["docker", "compose", "--env-file", str(OUT / "runtime.env"),
            "--project-name", PROJECT, "--profile", "driver", *overlays, *args]


def python_test_mounts():
    if not PYTHON_RELEASE:
        return []
    return ["-v", PROJECT + "_spell-python-requests:/python-requests",
            "-v", PROJECT + "_spell-python-responses:/python-responses",
            "-e", "SPELL_TEST_PYTHON_REQUEST_DIR=/python-requests",
            "-e", "SPELL_TEST_PYTHON_RESPONSE_DIR=/python-responses",
            "--tmpfs", "/tmp:size=512m"]


def pinned_node_tools():
    lock = json.loads((ROOT / "scripts/release-toolchain-v191.json").read_bytes())
    paths = {row["name"]: Path(os.environ[row["base_directory"]]) / row["relative_path"]
             for row in lock["tools"] if row["name"] in {"node", "npm-cli"}}
    for row in lock["tools"]:
        if row["name"] in paths:
            require(hashlib.sha256(paths[row["name"]].read_bytes()).hexdigest() == row["sha256"], "Pinned Node tool differs")
    return paths["node"], paths["npm-cli"]


@contextmanager
def renewing_credential(renew, private_token: Path, *, interval=600):
    """Keep the parent credential current and settle renewal before accepting a gate."""
    stop = threading.Event()
    errors = []
    refresher = None
    def refresh_loop():
        while not stop.wait(interval):
            try:
                renew()
            except Exception:
                errors.append("DSS credential renewal failed")
                return
    try:
        renew()
        refresher = threading.Thread(target=refresh_loop, name="dss-gate-credential-refresh", daemon=True)
        refresher.start()
        yield
    finally:
        stop.set()
        if refresher is not None:
            refresher.join(timeout=60)
        private_token.unlink(missing_ok=True)
        private_token.with_suffix(".pending").unlink(missing_ok=True)
        require(refresher is None or not refresher.is_alive(), "DSS credential renewal did not terminate")
        require(not errors, "DSS credential renewal failed")


class Producer:
    def __init__(self, gate, *, resume_from=None):
        global LINUX_SOURCE, LINUX_PYTEST_EVIDENCE
        require(resume_from is None or (MINOR >= 19 and gate == "dss-validation"),
                "continuation is supported only for the DSS validation gate")
        require(not git("status", "--porcelain"), "qualification requires clean committed source")
        OUT.mkdir(parents=True, exist_ok=True)
        if gate not in {"prepare", "candidate"}:
            verify_candidate(policy())
        self.gate, self.source, self.binding = gate, git("rev-parse", "HEAD"), fingerprint()
        self.commands = []
        self.resume_from = Path(resume_from).resolve() if resume_from is not None else None
        self.linux_source = None
        self.pytest_evidence = None
        LINUX_SOURCE = None
        LINUX_PYTEST_EVIDENCE = None
        if gate in {"candidate", "sqlite", "postgresql", "compose", "documentation", "tooling",
                    "reference-generators", "replay", "image-probe", "supply-chain", "dss-validation"}:
            self.linux_source = linux_source_snapshot(gate=gate)
            LINUX_SOURCE = self.linux_source
        if gate in PYTEST_GATES:
            self.pytest_evidence = create_linux_pytest_evidence(gate, self.source)
            start_linux_pytest_reader(self.pytest_evidence, self.linux_source)
            LINUX_PYTEST_EVIDENCE = self.pytest_evidence

    def run(self, command, *, cwd=ROOT, env=None, output=None, private=False, timeout=None):
        started = time.monotonic()
        result = subprocess.run([str(arg) for arg in command], cwd=cwd, env=env, capture_output=True, timeout=timeout)
        # Credentials are only captured in memory. They are never command arguments or logs.
        if not private:
            log = OUT / f"{self.gate}-{len(self.commands):02d}.log"
            log.write_bytes(result.stdout + result.stderr)
            if output:
                (OUT / output).write_bytes(result.stdout)
        def display(arg):
            value = str(arg)
            for base, label in ((str(ROOT), "<repository>"), (os.environ.get("LOCALAPPDATA"), "<LocalAppData>"),
                                (os.environ.get("ProgramFiles"), "<ProgramFiles>")):
                if base:
                    value = value.replace(base, label).replace(base.replace("\\", "/"), label)
            return value
        self.commands.append({"gate": self.gate, "source_commit": self.source,
                              "command": [display(arg) for arg in command],
                              "returncode": result.returncode,
                              "seconds": round(time.monotonic() - started, 3)})
        if self.pytest_evidence is not None and command[:3] == ['docker', 'run', '--rm']:
            collect_linux_pytest_evidence(self.pytest_evidence)
        require(result.returncode == 0, f"{self.gate} command failed; inspect its local log")
        return result.stdout

    def finish(self):
        if self.pytest_evidence is not None:
            require(self.pytest_evidence.get('source_after_verified')
                    and len(self.linux_source['audits']) == 2
                    and self.pytest_evidence['reader'].get('cleanup') == 'owned_stopped_reader_removed',
                    'Pytest post-run source audit or reader cleanup is missing')
        elif self.linux_source is not None:
            linux_source_snapshot(gate=self.gate, snapshot=self.linux_source)
        require(self.source == git("rev-parse", "HEAD") and self.binding == fingerprint(), "source changed during qualification")
        if self.pytest_evidence is not None:
            close_linux_pytest_evidence(self.pytest_evidence)
        write_json(OUT / f"{self.gate}.command.json", {"source_commit": self.source,
                   "source_fingerprint": self.binding, "commands": self.commands,
                   **({"linux_source_snapshot": self.linux_source} if self.linux_source is not None else {}),
                   **({'linux_pytest_evidence': self.pytest_evidence} if self.pytest_evidence is not None else {})})
        print(f"{self.gate}: PASS commands={len(self.commands)}")

    def execute(self):
        gate = self.gate
        if gate == "prepare":
            self.run(["docker", "build", "-t", QUALIFIER, "-f", "scripts/qualification-next.Dockerfile", "."])
            builds = [
                ("backend", "backend/Dockerfile", None), ("driver", "driver_host/Dockerfile", None),
                ("frontend", "proxy/Dockerfile", "frontend-build"), ("proxy", "proxy/Dockerfile", None),
            ] + ([("dss", "dss/Dockerfile", None), ("kafka", "dss/kafka.Dockerfile", None)] if MINOR >= 19 else [])
            for name, dockerfile, target in builds:
                command = ["docker", "build", "-t", IMAGES[name], "-f", dockerfile]
                self.run(command + (["--target", target] if target else []) + ["."])
            if PYTHON_RELEASE:
                self.run(["docker", "build", "-t", IMAGES["python"], "-f", "backend/python_runtime.Dockerfile",
                    "--build-arg", "SPELL_PYTHON_BACKEND_IMAGE=" + IMAGES["backend"], "."])
            runtime = OUT / "runtime.env"
            if not runtime.exists():
                runtime.write_bytes((f"SPELL_DB_PASSWORD={secrets.token_hex(24)}\n"
                    f"SPELL_JWT_HS256_SECRET={secrets.token_hex(32)}\nSPELL_IMAGE_TAG={TAG}\n"
                    "SPELL_DRIVER_ENABLED=true\nSPELL_ALLOW_LOCAL_DEV_TOKEN=false\nSPELL_PROXY_PORT=8080\n").encode())
            if MINOR >= 19:
                # Private environment remains private; the gate reset API is explicitly local.
                entries = dict(line.split("=", 1) for line in runtime.read_text().splitlines() if "=" in line)
                entries.update(SPELL_DSS_ENABLED="true", DSS_TEST_CONTROL_ENABLED="true")
                if PYTHON_RELEASE:
                    entries.update(SPELL_PYTHON_BACKEND_IMAGE=IMAGES["backend"],
                        SPELL_PYTHON_PROXY_IMAGE=IMAGES["proxy"], SPELL_PYTHON_IMAGE_TAG=TAG)
                runtime.write_bytes(("\n".join(f"{key}={value}" for key, value in entries.items()) + "\n").encode())
            previous_minor = MINOR if PYTHON_RELEASE else MINOR - 1
            previous_env = ROOT / f".qualification/v{previous_minor}/final/runtime.env"
            if previous_env.exists():
                previous_overlays = ["-f", "compose.yaml", "-f", "compose.procedures.yaml", "-f", "compose.python.yaml"] if PYTHON_RELEASE else []
                self.run(["docker", "compose", "--env-file", str(previous_env),
                          "--project-name", f"spellv0{previous_minor}release", "--profile", "driver", *previous_overlays, "stop"])
            self.run(compose("up", "--no-build" if PYTHON_RELEASE else "--build", "-d", "--wait"))
            if MINOR >= 19:
                self.run(compose("exec", "-T", "dss", "python", "-m", "dss.control", "RESUME"))
                # Admit the real bundled simulator observation context; no test data injection.
                self.run(compose("exec", "-T", "backend", "python", "/app/scripts/seed_dss_v19.py",
                    "--confirm", "LOCAL_SYNTHETIC_NON_CUI_ONLY", "--context-id", "simulator"))
            # Compose image labels participate in image identity. Audit the running images.
            runtime_images = (("backend", "backend"), ("spell-driver", "driver"), ("proxy", "proxy"))
            if MINOR >= 19:
                runtime_images += (("dss", "dss"), ("kafka", "kafka"))
            if PYTHON_RELEASE:
                runtime_images += (("python-runtime", "python"),)
            for service, name in runtime_images:
                container = self.run(compose("ps", "--quiet", service)).decode().strip()
                identity = self.run(["docker", "inspect", "--format", "{{.Image}}", container]).decode().strip()
                self.run(["docker", "tag", identity, IMAGES[name]])
            for database in ("spell_test", "spell_migration_test"):
                existing = self.run(compose("exec", "-T", "postgres", "psql", "-U", "spell", "-d", "spell", "-tAc",
                                           f"SELECT 1 FROM pg_database WHERE datname='{database}'"))
                if existing.strip() != b"1":
                    self.run(compose("exec", "-T", "postgres", "createdb", "-U", "spell", database))
            entries = dict(line.split("=", 1) for line in runtime.read_text().splitlines())
            password = entries["SPELL_DB_PASSWORD"]
            (OUT / "postgres.env").write_bytes((
                f"SPELL_TEST_DATABASE_URL=postgresql+psycopg://spell:{password}@postgres:5432/spell_test\n"
                f"SPELL_MIGRATION_TEST_DATABASE_URL=postgresql+psycopg://spell:{password}@postgres:5432/spell_migration_test\n").encode())
        elif gate == "candidate":
            deselections = [arg for name in policy().get("candidate_deselections", []) for arg in ("--deselect", name)]
            self.run(docker_python("-m", "pytest", *policy()["candidate_files"], *deselections, "-q", "-p", "no:cacheprovider",
                                   "--tb=short", "--junitxml=/evidence/candidate.xml", extra=python_test_mounts()))
        elif gate in {"sqlite", "postgresql", "compose", "documentation", "tooling"}:
            tests = {
                "sqlite": ["backend/tests", "driver_host/tests"], "postgresql": ["backend/tests"],
                "compose": COMPOSE_TESTS,
                "documentation": DOC_TESTS, "tooling": TOOL_TESTS,
            }[gate]
            extra, network = [], "none"
            if gate == "postgresql":
                extra = ["--env-file", str(OUT / "postgres.env")]
                network = PROJECT + "_spell-internal"
            elif gate == "compose":
                extra = ["-v", "/var/run/docker.sock:/var/run/docker.sock", "-e", "SPELL_RUN_COMPOSE_RUNTIME_TESTS=1",
                         "-e", f"SPELL_IMAGE_TAG={TAG}-isolation"]
                network = "bridge"
            if gate in {'sqlite', 'postgresql'}:
                extra += python_test_mounts()
                self.run(docker_python('-c', MODULE_PYTEST, gate, json.dumps(tests), network=network, extra=extra))
            else:
                self.run(docker_python("-m", "pytest", *tests, "-q", "-p", "no:cacheprovider", "--tb=short",
                                       f"--junitxml=/evidence/{gate}.xml", network=network, extra=extra))
        elif gate in {"frontend", "frontend-build"}:
            npm = list(pinned_node_tools()) if PYTHON_RELEASE else [shutil.which("npm.cmd") or shutil.which("npm")]
            if gate == "frontend":
                self.run([*npm, "ci", "--ignore-scripts"], cwd=ROOT / "frontend")
                self.run([*npm, "test", "--", "--run", "--reporter=junit", f"--outputFile={OUT / 'frontend.xml'}"], cwd=ROOT / "frontend")
            else:
                self.run([*npm, "run", "build"], cwd=ROOT / "frontend")
        elif gate == "replay":
            self.run(docker_python("-m", "scripts.qualify_legacy_observation_v12", "--soak-seconds", "60", "--output", "/evidence/replay.json"))
            if MINOR >= 14:
                self.run(docker_python("-m", "scripts.qualify_telemetry_adapter_v14", "--output", "/evidence/adapter-soak.json"))
            if MINOR >= 15:
                self.run(docker_python("-m", "scripts.qualify_shadow_pilot_v15", "--output", "/evidence/pilot-soak.json"))
        elif gate == "reference-generators":
            generator = f"scripts.generate_reference_runner_v{MINOR}" if MINOR >= 17 else "scripts.generate_reference_runner_v10"
            self.run(docker_python("-m", generator, "--check"))
            if MINOR >= 19:
                self.run(docker_python("-m", "scripts.generate_dss_contract", "--check"))
                self.run(docker_python("-m", "scripts.generate_kafka_security_dockerfile", "--check"))
            if PYTHON_RELEASE:
                self.run(docker_python("-m", "scripts.qualify_dss_v191", "--check-contract"))
            self.run(docker_python("-m", "scripts.qualify_reference_examples_v10", "--output", "/evidence/reference-examples.json"))
            if MINOR >= 16:
                language_qualifier = f"scripts.qualify_language_v{MINOR}"
                self.run(docker_python("-m", language_qualifier, "--output", "/evidence/language-conformance.json"))
        elif gate == "dss-validation":
            require(MINOR >= 19, "DSS gate requires v0.19 or later")
            identities = {name: self.run(["docker", "image", "inspect", "--format", "{{.Id}}", image]).decode().strip()
                          for name, image in IMAGES.items()}
            write_json(OUT / "dss-bindings.json", {"source_commit": self.source, "image_ids": identities})
            issuer = compose("run", "--rm", "--no-deps", "-e", "SPELL_ALLOW_LOCAL_DEV_TOKEN=true",
                "backend", "python", "/app/scripts/issue_dev_token.py", "--subject", "v019-dss-delivery-gate",
                "--role", "operator", "--lifetime", "900")
            private_token = OUT / "dss-gate.token"
            def renew():
                token = self.run(issuer, private=True, timeout=45).decode().strip()
                require(token.count(".") == 2 and "\n" not in token, "DSS gate token issuer output invalid")
                temporary = private_token.with_suffix(".pending")
                temporary.write_bytes(token.encode())
                temporary.replace(private_token)
            with renewing_credential(renew, private_token):
                resume_args, resume_mount = [], []
                if self.resume_from is not None:
                    require(self.resume_from.is_dir() and self.resume_from != OUT.resolve(),
                            "DSS continuation requires a separate retained archive")
                    resume_args = ["--resume-from", "/retained-dss"]
                    resume_mount = ["-v", f"{self.resume_from.as_posix()}:/retained-dss:ro"]
                self.run(docker_python("-m", "scripts.qualify_dss_v191" if PYTHON_RELEASE else "scripts.qualify_dss_v19", "--backend-url", "http://proxy:8080",
                    "--dss-url", "http://dss:8081/api/v1", "--bindings", "/evidence/dss-bindings.json",
                    "--output", "/evidence/dss-validation.json", *resume_args,
                    network=PROJECT + "_spell-internal",
                    extra=["-e", "SPELL_DSS_GATE_TOKEN_FILE=/evidence/dss-gate.token", *resume_mount]))
        elif gate == "browser":
            token = self.run(compose("run", "--rm", "--no-deps", "-e", "SPELL_ALLOW_LOCAL_DEV_TOKEN=true",
                "backend", "python", "/app/scripts/issue_dev_token.py", "--subject", f"v0{MINOR}-browser-qualification",
                "--role", "operator", "--lifetime", "900"), private=True).decode().strip()
            require(token.count(".") == 2 and "\n" not in token, "token issuer output invalid")
            env = dict(os.environ, SPELL_E2E_TOKEN=token, SPELL_REAL_BACKEND="1", SPELL_E2E_BASE_URL="http://127.0.0.1:8080",
                       PLAYWRIGHT_JUNIT_OUTPUT_FILE=str(OUT / "browser.xml"), PLAYWRIGHT_JUNIT_INCLUDE_PROJECT_IN_TEST_NAME="1",
                       SPELL_E2E_OUTPUT_DIRECTORY=str(OUT / "browser"))
            if MINOR >= 15:
                reviewer = self.run(compose("run", "--rm", "--no-deps", "-e", "SPELL_ALLOW_LOCAL_DEV_TOKEN=true",
                    "backend", "python", "/app/scripts/issue_dev_token.py", "--subject", "v015-independent-review-test",
                    "--role", "admin", "--lifetime", "900"), private=True).decode().strip()
                require(reviewer.count(".") == 2 and "\n" not in reviewer, "review token issuer output invalid")
                env["SPELL_E2E_REVIEW_TOKEN"] = reviewer
            node = pinned_node_tools()[0] if PYTHON_RELEASE else shutil.which("node")
            self.run([node, "node_modules/@playwright/test/cli.js", "test", "legacy-observation-v12-real.spec.ts",
                      *policy()["feature_browser_specs"], "language-reference-v10-real.spec.ts", "--workers=1", "--retries=0", "--reporter=junit"], cwd=ROOT / "frontend", env=env)
        elif gate == "image-probe":
            self.run(docker_python("-c", "import pathlib; files=[*pathlib.Path('backend').rglob('*.py'),*pathlib.Path('driver_host').rglob('*.py'),*pathlib.Path('dss').rglob('*.py')]; [compile(p.read_bytes(),str(p),'exec') for p in files]; print('compilation PASS',len(files))"))
            self.run(docker_python("-m", "scripts.probe_images_next", "--output", "/evidence/image-probe.json", network="none",
                                  extra=["-v", "/var/run/docker.sock:/var/run/docker.sock"]))
        elif gate == "supply-chain":
            extra_locks = ["-r", "driver_host/requirements.hashes.lock", "-r", "dss/requirements.hashes.lock"] if MINOR >= 19 else []
            self.run(docker_python("-m", "pip_audit", "--disable-pip", "--no-deps", "-r", "backend/requirements.hashes.lock", *extra_locks,
                                  "-f", "json", "-o", "/evidence/python-audit.json", network="bridge"))
            npm = list(pinned_node_tools()) if PYTHON_RELEASE else [shutil.which("npm.cmd") or shutil.which("npm")]
            self.run([*npm, "audit", "--json"], cwd=ROOT / "frontend", output="npm-audit.json")
            sbom = Path(os.environ["LOCALAPPDATA"]) / "OpenBEXI/release-toolchain/docker-sbom-0.6.0-windows-amd64/docker-sbom.exe"
            rows = {}
            for name, image in IMAGES.items():
                identity = self.run(["docker", "image", "inspect", "--format", "{{.Id}}", image]).decode().strip()
                self.run([str(sbom), "sbom", identity, "--format", "cyclonedx-json", "--output", str(OUT / f"{name}.cdx.json")])
                self.run(["docker", "scout", "cves", identity, "--format", "sarif", "--output", str(OUT / f"{name}.sarif.json")])
                scan = json.loads((OUT / f"{name}.sarif.json").read_bytes())
                rules = scan["runs"][0]["tool"]["driver"]["rules"]
                probes = json.loads((OUT / "image-probe.json").read_bytes())
                require(probes["images"][name]["image_id"] == identity, "applicability probe image differs")
                resolutions = resolve(scan, probes["images"][name])
                rows[name] = {"image_id": identity, "high": 0, "critical": 0,
                                "resolved_findings": resolutions,
                              "sbom_sha256": hashlib.sha256((OUT / f"{name}.cdx.json").read_bytes()).hexdigest(),
                              "scan_sha256": hashlib.sha256((OUT / f"{name}.sarif.json").read_bytes()).hexdigest(),
                                "lower_severity_disposition": {"advisories": [r["id"] for r in rules if float(r["properties"].get("security-severity", "0")) < 7],
                                  "review_by": "2026-10-30", "decision": "Restricted local synthetic environment; monitor vendor fixes and rebuild before broader use."}}
            write_json(OUT / "supply-chain.json", {"schema_version": f"spell.v{MINOR}.supply-chain/1", "images": rows})
            self.run(docker_python("-c", "import json,pathlib; from scripts.validate_cyclonedx_v04 import validate_document,run_negative_self_test; p=pathlib.Path('/evidence'); names=" + repr(list(IMAGE_NAMES)) + "; versions={n:validate_document((p/(n+'.cdx.json')).read_text(),n) for n in names}; run_negative_self_test(); (p/'sbom-validation.json').write_bytes((json.dumps({'schemas':versions,'negative_tamper_rejected':True,'validator':'cyclonedx-python-lib/11.11.0'},sort_keys=True)+'\\n').encode()); print('strict CycloneDX schemas: PASS', len(names))"))
        else:
            raise ValueError("unknown gate")
        self.finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gate", choices=("prepare", "candidate", "sqlite", "postgresql", "compose", "documentation", "tooling",
        "frontend", "frontend-build", "replay", "reference-generators", "dss-validation", "browser", "image-probe", "supply-chain", "assemble"))
    parser.add_argument("--resume-from", type=Path)
    args = parser.parse_args()
    if args.resume_from is not None and (MINOR < 19 or args.gate != "dss-validation"):
        parser.error("--resume-from is supported only for DSS validation")
    if args.gate == "assemble":
        captures = [json.loads(path.read_bytes()) for path in sorted(OUT.glob("*.command.json")) if path.name != "candidate.command.json"]
        require(len(captures) == (14 if MINOR >= 19 else 13), "missing canonical gate capture")
        require(all(row["source_commit"] == git("rev-parse", "HEAD") and row["source_fingerprint"] == fingerprint() for row in captures), "capture source differs")
        write_json(OUT / "commands.json", {
            "source_commit": git("rev-parse", "HEAD"),
            "commands": [command for row in captures for command in row["commands"]],
            "linux_source_snapshots": {path.name.removesuffix('.command.json'): row['linux_source_snapshot']
                for path, row in zip(sorted(path for path in OUT.glob('*.command.json')
                                            if path.name != 'candidate.command.json'), captures)
                if 'linux_source_snapshot' in row},
            "linux_pytest_evidence": {path.name.removesuffix('.command.json'): row['linux_pytest_evidence']
                for path, row in zip(sorted(path for path in OUT.glob('*.command.json')
                                            if path.name != 'candidate.command.json'), captures)
                if 'linux_pytest_evidence' in row},
        })
    else:
        Producer(args.gate, resume_from=args.resume_from).execute()


if __name__ == "__main__":
    main()
