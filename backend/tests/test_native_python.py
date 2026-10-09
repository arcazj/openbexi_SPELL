from __future__ import annotations

import hashlib
import os
import time
import uuid
from pathlib import Path

import pytest

from backend.native_python import IR_VERSION, LANGUAGE_PROFILE, canonical, script_step, validate_ir, breakpoint_lines
from backend.native_python_protocol import PythonClient, READY, RESPONSE_SCHEMA, TERMINAL, read_json, write_json
from backend.development_domain import DevelopmentCorruptionError
from backend.ir_v03 import IRValidationError
from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError
from backend.serialization import execution_dict
from backend.tests.conftest import wait_for_state
from backend.tests.test_api_execution import create_execution
from backend.tests.test_v11_operator_integration import _acquire_control
from backend.tests.test_operator_composition_v18 import _proof
from backend.operator_service import OperatorValidationError, OperatorAuthorizationError
from backend.models import Execution
from backend.operator_models import OperatorCommand

HEADER = '# @language-profile python-stdlib/3.13\n'
ROOT = Path(__file__).resolve().parents[2]
EMPTY_DEBUG = {'line': None, 'reason': None, 'sequence': 0, 'control_revision': 0}


def test_catalog_requires_explicit_profile_and_preserves_exact_source(tmp_path):
    raw = (HEADER + 'import sys\r\nprint("café", sys.version_info.major)\r\n').encode()
    (tmp_path / 'native.py').write_bytes(raw)
    (tmp_path / 'unmarked.py').write_text('raise RuntimeError("never import me")')
    catalog = ProcedureCatalog(tmp_path)
    [procedure] = catalog.list()
    assert procedure.id == 'native' and procedure.ir_version == IR_VERSION
    assert procedure.source.encode() == raw
    assert procedure.sha256 == hashlib.sha256(raw).hexdigest()
    assert procedure.steps[0]['source_sha256'] == procedure.sha256
    with pytest.raises(ProcedureValidationError):
        catalog.validate_source('import os\nprint(os.environ)', 'unmarked.spell.py')


@pytest.mark.parametrize('field,value', [('source_sha256', '0'*64), ('source', HEADER+'print("changed")'),
    ('runtime_profile', 'other'), ('source_name', '../escape.py'), ('line', 2), ('index', True),
    ('step_over_target', 0), ('lexical_frame_id', 'other'), ('extra', None)])
def test_source_and_target_metadata_are_independently_validated(field, value):
    step = script_step(HEADER+'print("original")', 'test.py')
    step[field] = value
    with pytest.raises(IRValidationError):
        validate_ir(IR_VERSION, [step])


@pytest.mark.parametrize('source', ['print(1)', HEADER+'\x00', HEADER+'print(', HEADER+'#' * 100001])
def test_source_must_be_opted_in_bounded_and_parseable(source):
    with pytest.raises(IRValidationError):
        script_step(source, 'test.py')


def test_python_checkpoint_does_not_recover_live_objects():
    steps = [script_step(HEADER+'print(1)', 'test.py')]
    for position, variables in [(0, {'live_object': {}}), (1, {}), (2, {}), (True, {})]:
        with pytest.raises(IRValidationError):
            validate_ir(IR_VERSION, steps, start_step=position, checkpoint_variables=variables)
    result = {'python_completed': True, 'python_exit_code': 0, 'python_stdout_lines': 1, 'python_stderr_lines': 0}
    assert validate_ir(IR_VERSION, steps, start_step=1, checkpoint_variables=result).checkpoint_variables == result


def test_protocol_rejects_wrong_binding_and_rewritten_output(tmp_path):
    requests, responses = tmp_path/'requests', tmp_path/'responses'
    requests.mkdir(); responses.mkdir(); write_json(responses/'ready.json', READY)
    client = PythonClient({'requests': str(requests), 'responses': str(responses)}, str(uuid.uuid4()), 1,
                          script_step(HEADER+'print(1)', 'test.py'))
    frame = dict(schema_version=RESPONSE_SCHEMA, request_id=client.id, request_sha256=client.digest,
                 state='RUNNING', revision=1, control_revision=0, stdout='first\n', stderr='', exit_code=None, error_code='', debug=EMPTY_DEBUG)
    path = responses/(client.id+'.response.json')
    try:
        write_json(path, {**frame, 'request_sha256': '0'*64})
        with pytest.raises(ValueError, match='binding'):
            client.poll()
        write_json(path, frame, replace=True); assert client.poll()['stdout'] == 'first\n'
        for changed in [{**frame, 'stdout': 'first\nsecond'}, {**frame, 'revision': 2, 'stdout': 'different'}]:
            write_json(path, changed, replace=True)
            with pytest.raises(ValueError): client.poll()
    finally:
        client.close()


def test_poll_accepts_a_complete_atomic_replacement_between_stat_and_open(tmp_path, monkeypatch):
    requests, responses = tmp_path/'requests', tmp_path/'responses'
    requests.mkdir(); responses.mkdir(); write_json(responses/'ready.json', READY)
    client = PythonClient({'requests': str(requests), 'responses': str(responses)}, str(uuid.uuid4()), 1,
                          script_step(HEADER+'print(1)', 'test.py'))
    frame = dict(schema_version=RESPONSE_SCHEMA, request_id=client.id, request_sha256=client.digest,
                 state='RUNNING', revision=1, control_revision=0, stdout='first\n', stderr='', exit_code=None, error_code='', debug=EMPTY_DEBUG)
    path = responses/(client.id+'.response.json')
    write_json(path, frame)
    original_open = os.open
    replacements = []
    def replacing_open(filename, flags, *args, **kwargs):
        if Path(filename) == path and not replacements:
            replacements.append(True)
            write_json(path, {**frame, 'revision': 2, 'stdout': 'first\nsecond\n'}, replace=True)
        return original_open(filename, flags, *args, **kwargs)
    monkeypatch.setattr(os, 'open', replacing_open)
    try:
        result = client.poll()
        assert result['revision'] == 2 and result['stdout'] == 'first\nsecond\n'
        assert replacements == [True]
    finally:
        client.close()


@pytest.mark.parametrize('error,mutable,attempts', [
    ('changed before read', False, 1), ('changed before read', True, 4),
    ('changed while reading', True, 1), ('is not a regular file', True, 1)])
def test_atomic_read_retries_are_bounded_and_do_not_hide_corruption(monkeypatch, error, mutable, attempts):
    calls = []
    def corrupt_read(*args, **kwargs):
        calls.append(True)
        raise DevelopmentCorruptionError('Python runtime protocol '+error)
    monkeypatch.setattr('backend.native_python_protocol.read_protocol_file', corrupt_read)
    with pytest.raises(DevelopmentCorruptionError, match=error):
        read_json(Path('/unused/response.json'), mutable=mutable)
    assert len(calls) == attempts


@pytest.fixture
def runtime_configuration():
    requests = os.environ.get('SPELL_TEST_PYTHON_REQUEST_DIR')
    responses = os.environ.get('SPELL_TEST_PYTHON_RESPONSE_DIR')
    if not requests or not responses:
        pytest.skip('requires the isolated compose.python.yaml service')
    return {'requests': requests, 'responses': responses}


def job(configuration, source, *, arguments=None, timeout=30, start_paused=False, breakpoints=None):
    return PythonClient(configuration, str(uuid.uuid4()), 1, script_step(source, 'test_Python.py'),
                        arguments=arguments, timeout_seconds=timeout, start_paused=start_paused, breakpoints=breakpoints)


def wait(client, states=TERMINAL, timeout=35):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        value = client.poll()
        if value and value['state'] in states and value['control_revision'] >= client.command_revision:
            return value
        if value and value['state'] in TERMINAL:
            raise AssertionError(f'Python runtime finished before {states}: {value}')
        time.sleep(.02)
    raise AssertionError(f'Python runtime did not reach {states}: {client.last}')


def test_executable_line_inventory_is_nonexecuting_and_excludes_comments():
    source = HEADER+'# comment\n\nraise AssertionError("must never execute")\n'
    assert breakpoint_lines(source) == [4]
    assert breakpoint_lines(HEADER+'def f():\n return (\n  1 +\n  2\n )\nf()\n')


def test_breakpoint_stops_before_each_loop_iteration_and_removal_continues(runtime_configuration):
    client = job(runtime_configuration, HEADER+'for i in range(3):\n print(i)\nprint("done")\n',
                 breakpoints=[3])
    try:
        first = wait(client, {'PAUSED'})
        assert first['debug']['line'] == 3 and first['debug']['reason'] == 'breakpoint'
        assert first['stdout'] == ''
        client.command('RESUME')
        second = wait(client, {'PAUSED'})
        assert second['debug']['line'] == 3 and second['stdout'] == '0\n'
        assert second['debug']['sequence'] == first['debug']['sequence'] + 1
        client.configure([])
        client.command('RESUME')
        result = wait(client)
        assert result['state'] == 'COMPLETED' and result['stdout'] == '0\n1\n2\ndone\n'
    finally:
        client.close()


@pytest.mark.parametrize('action,expected_line,expected_output', [
    ('STEP', 3, ''), ('STEP_OVER', 6, 'inner\n')])
def test_function_step_and_step_over_stop_before_the_correct_line(runtime_configuration, action, expected_line, expected_output):
    source = HEADER+'def f():\n print("inner")\n return 3\nvalue = f()\nprint("after")\nprint("done")\n'
    client = job(runtime_configuration, source, breakpoints=[5])
    try:
        assert wait(client, {'PAUSED'})['debug']['line'] == 5
        client.configure([])
        client.command(action)
        stopped = wait(client, {'PAUSED'})
        assert stopped['debug']['line'] == expected_line and stopped['stdout'] == expected_output, stopped
        client.command('RUN_TO_LINE', target_line=7)
        stopped = wait(client, {'PAUSED'})
        assert stopped['debug']['line'] == 7 and stopped['stdout'] == 'inner\nafter\n', stopped
        client.command('STEP')
        result = wait(client)
        assert result['state'] == 'COMPLETED' and result['stdout'] == 'inner\nafter\ndone\n', result
    finally:
        client.close()


def test_abort_from_entry_pause_executes_no_source(runtime_configuration):
    client = job(runtime_configuration, HEADER+'print("must not run")\n', start_paused=True)
    try:
        stopped = wait(client, {'PAUSED'})
        assert stopped['debug']['line'] == 2 and stopped['debug']['reason'] == 'entry'
        client.command('ABORT')
        result = wait(client)
        assert result['state'] == 'ABORTED' and result['stdout'] == ''
    finally:
        client.close()


def test_malformed_debug_controls_fail_closed_without_execution(runtime_configuration):
    client = job(runtime_configuration, HEADER+'print("must not run")\n', start_paused=True)
    try:
        wait(client, {'PAUSED'})
        write_json(client.requests/(client.id+'.control.json'), {
            'request_id': client.id, 'request_sha256': '0'*64, 'revision': 1,
            'action': 'STEP', 'target_line': None, 'breakpoints': []}, replace=True)
        result = wait(client)
        assert result['state'] == 'FAILED' and result['error_code'] == 'PYTHON_RUNNER_FAILURE'
        assert result['stdout'] == ''
    finally:
        client.close()


def test_updated_python_script_runs_all_39_topics(runtime_configuration):
    source = (ROOT/'procedures/test_Python.py').read_bytes().decode()
    client = job(runtime_configuration, source)
    try:
        result = wait(client)
        assert result['state'] == 'COMPLETED', result['stderr'] + result['stdout'][-2000:]
        assert result['exit_code'] == 0 and result['stderr'] == ''
        assert '39 topic(s), 0 optional capability check(s) skipped.' in result['stdout'], result['stdout']
        assert 'multiprocessing IPC result: 49' in result['stdout']
        assert 'loopback TCP echo:' in result['stdout']
        assert 'subprocess nonzero status: 7' in result['stdout']
    finally:
        client.close()


def test_updated_python_script_completes_after_pause_and_resume(runtime_configuration):
    source = (ROOT/'procedures/test_Python.py').read_bytes().decode()
    client = job(runtime_configuration, source)
    try:
        revision = client.command('PAUSE')
        paused = wait(client, {'PAUSED'})
        assert paused['control_revision'] == revision
        output = paused['stdout']
        time.sleep(.2)
        assert client.poll()['stdout'] == output
        client.command('RESUME')
        result = wait(client)
        assert result['state'] == 'COMPLETED' and result['exit_code'] == 0, result
        assert result['stderr'] == ''
        assert '261 check(s), 39 topic(s), 0 optional capability check(s) skipped.' in result['stdout']
    finally:
        client.close()


@pytest.mark.parametrize('body,state,exit_code', [('print("before failure"); raise AssertionError("visible failure")', 'FAILED', 1),
    ('import sys; print("bad", file=sys.stderr); sys.exit(7)', 'FAILED', 7), ('print("ok")', 'COMPLETED', 0)])
def test_exit_and_error_output_are_not_silenced(runtime_configuration, body, state, exit_code):
    client = job(runtime_configuration, HEADER+body)
    try:
        result = wait(client)
        assert result['state'] == state and result['exit_code'] == exit_code
        if state == 'FAILED': assert result['stderr']
    finally: client.close()


def test_filesystem_identity_credentials_and_external_network_are_isolated(runtime_configuration):
    source = HEADER+'''import os, pathlib, socket, ctypes
assert os.getuid() == os.geteuid() == 20000
assert not any(k in os.environ for k in ('SPELL_JWT_HS256_SECRET', 'DATABASE_URL', 'SPELL_DRIVER_CLIENT_KEY'))
for path in ('/app/backend', '/proc', '/run/spell-driver-client', '/var/lib/openbexi-spell'):
    assert not pathlib.Path(path).exists(), path
try: os.setuid(0)
except PermissionError: pass
else: raise AssertionError('privilege escalation')
try: pathlib.Path('/usr/local/bin/owned').write_text('bad')
except OSError: pass
else: raise AssertionError('immutable runtime was writable')
try: socket.create_connection(('192.0.2.1', 443), timeout=.2)
except OSError: pass
else: raise AssertionError('external network is reachable')
print('isolated')
'''
    client = job(runtime_configuration, source)
    try:
        result = wait(client)
        assert result['state'] == 'COMPLETED' and result['stdout'] == 'isolated\n', result
    finally: client.close()


def test_pause_resume_and_abort_stop_the_actual_process(runtime_configuration):
    client = job(runtime_configuration, HEADER+'import time\nfor i in range(200):\n print(i, flush=True); time.sleep(.05)')
    def output_after(previous):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            frame = client.poll()
            if (frame and frame['state'] == 'RUNNING'
                    and frame['control_revision'] >= client.command_revision
                    and len(frame['stdout']) > len(previous)):
                return frame['stdout']
            time.sleep(.02)
        raise AssertionError(f'Running Python process did not produce bounded output: {client.last}')
    try:
        wait(client, {'RUNNING'}); output_after('')
        pause = client.command('PAUSE'); stopped = wait(client, {'PAUSED'})
        assert stopped['control_revision'] == pause
        time.sleep(.2); first = client.poll()['stdout']; time.sleep(.3)
        assert client.poll()['stdout'] == first
        resume = client.command('RESUME'); resumed = wait(client, {'RUNNING'})
        assert resumed['control_revision'] == resume
        assert len(output_after(first)) > len(first)
        client.command('PAUSE'); wait(client, {'PAUSED'})
        abort = client.command('ABORT'); result = wait(client)
        assert result['state'] == 'ABORTED' and result['control_revision'] == abort
    finally: client.close()


@pytest.mark.parametrize('body,timeout,state', [('import time; time.sleep(5)', .2, 'TIMED_OUT'),
                                              ('print("x" * 300000)', 5, 'OUTPUT_LIMIT')])
def test_run_and_output_limits(runtime_configuration, body, timeout, state):
    client = job(runtime_configuration, HEADER+body, timeout=timeout)
    try: assert wait(client)['state'] == state
    finally: client.close()


def test_worker_loss_cancels_without_replay(runtime_configuration):
    client = job(runtime_configuration, HEADER+'import time; print("once", flush=True); time.sleep(20)')
    try:
        wait(client, {'RUNNING'}); time.sleep(3.5)
        result = wait(client)
        assert result['state'] == 'ABORTED' and result['error_code'] == 'PYTHON_WORKER_LOST'
        assert result['stdout'] == 'once\n'
    finally: client.close()


@pytest.fixture
def procedures_dir():
    return ROOT/'procedures'


def python_controls(client, operator_headers, viewer_headers, identity):
    supervisor = client.app.state.supervisor
    snapshot = wait_for_state(client, identity, viewer_headers, {'paused'})
    headers, lease = _acquire_control(client, operator_headers, identity, snapshot, 'python-debug')
    proof = _proof(headers, lease)
    proof['controller_lease_id'] = proof.pop('lease_id')
    def command(action, target=None):
        operation = client.app.state.operator_service.accept_operator_command(identity, action,
            supervisor.get_execution(identity).revision, idempotency_key=str(uuid.uuid4()),
            role='operator', reason='Python debugger check', target=target or {}, **proof)
        assert operation['state'] == 'ACCEPTED', operation
        supervisor.dispatch_operator_command(operation)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            with client.app.state.session_factory() as session:
                settled = session.get(OperatorCommand, operation['id'])
                if settled.state in {'SETTLED', 'FAILED', 'CANCELLED', 'SUPERSEDED'}:
                    assert settled.state == 'SETTLED', settled.result_payload
                    return operation
            time.sleep(.02)
        raise AssertionError('Python control did not settle')
    return command, proof


def test_executor_runs_exact_python_source_and_commits_only_success(client, operator_headers, viewer_headers, runtime_configuration):
    client.app.state.supervisor.python_runtime_configuration = runtime_configuration
    identity = create_execution(client, operator_headers, 'test_Python')
    command, _ = python_controls(client, operator_headers, viewer_headers, identity)
    command('RUN')
    result = wait_for_state(client, identity, viewer_headers, {'completed', 'failed', 'recovery_required'}, timeout=40)
    execution = result['execution']
    assert execution['state'] == 'completed', [(e['event_type'], e['payload']) for e in result['events']
        if e['event_type'] in ('worker.crashed', 'worker.consumer_failed', 'worker.command_ack_timeout',
                              'procedure.error', 'execution.state_changed', 'execution.recovery_required')]
    assert execution['variables']['python_completed'] is True
    assert execution['variables']['python_exit_code'] == 0 and execution['current_step'] == 1
    assert execution['source_controls'] == {'breakpoints': True, 'run_to_line': True,
        'executable_lines': breakpoint_lines(execution['source'])}
    events = client.get(f'/api/v1/executions/{identity}/events?limit=1000', headers=viewer_headers).json()['items']
    logs = '\n'.join(e['payload']['message'] for e in events if e['event_type'] == 'procedure.log')
    assert '39 topic(s), 0 optional capability check(s) skipped.' in logs
    assert '261 check(s)' in logs
    # Reopening/refreshing a finished procedure must retain every output line,
    # including the first topics outside the general 200-event snapshot window.
    reopened = client.get(f'/api/v1/executions/{identity}/snapshot', headers=viewer_headers).json()
    assert [e['payload']['message'] for e in reopened['logs']] == [
        e['payload']['message'] for e in events if e['event_type'] == 'procedure.log']
    assert len(reopened['logs']) == execution['variables']['python_stdout_lines'] == 345
    assert not any(e['event_type'].startswith('procedure.telecommand_') for e in events)
    [receipt] = [e['payload'] for e in events if e['event_type'] == 'procedure.python_result']
    assert receipt['source_sha256'] == execution['procedure_hash'] and receipt['exit_code'] == 0


def test_missing_runtime_fails_admission_clearly(client, operator_headers):
    response = client.post('/api/v1/executions', headers=operator_headers, json={
        'procedure_id': 'test_Python', 'context_id': 'simulator', 'reason': 'missing runtime', 'idempotency_key': 'missing-python'})
    assert response.status_code == 409 and 'compose.python.yaml' in response.text


def test_executor_debugger_tracks_source_line_and_settles_step_and_run_to_line(client, operator_headers, viewer_headers, runtime_configuration):
    supervisor = client.app.state.supervisor
    supervisor.python_runtime_configuration = runtime_configuration
    source = HEADER+'def f():\n print("inner")\n return 3\nvalue = f()\nprint("after")\nprint("done")\n'
    procedure = client.app.state.catalog.validate_source(source, 'python_debug.py')
    execution = supervisor.create_execution(procedure, actor='pytest-operator', role='operator',
        reason='Python line debugger', idempotency_key='python-debug', automatic=True)
    command, proof = python_controls(client, operator_headers, viewer_headers, execution.id)
    def snapshot():
        return client.get(f'/api/v1/executions/{execution.id}/snapshot', headers=viewer_headers).json()
    assert snapshot()['execution']['current_line'] == 2
    breakpoint_proof = {**proof, 'lease_id': proof['controller_lease_id']}
    breakpoint_proof.pop('controller_lease_id')
    service = client.app.state.operator_service
    service.put_breakpoint(execution.id, 5, one_shot=False,
        expected_execution_revision=supervisor.get_execution(execution.id).revision,
        idempotency_key='python-add-breakpoint', reason='pause before calling f', **breakpoint_proof)
    command('RUN')
    wait_for_state(client, execution.id, viewer_headers, {'paused'})
    assert snapshot()['execution']['current_line'] == 5
    assert snapshot()['logs'] == []
    command('STEP')
    wait_for_state(client, execution.id, viewer_headers, {'paused'})
    assert snapshot()['execution']['state'] == 'paused'
    assert snapshot()['execution']['current_line'] == 3
    assert snapshot()['execution']['current_step'] == 0  # No replay checkpoint at a line stop.
    command('RUN', {'line': 7, 'source_digest': execution.procedure_hash})
    deadline = time.monotonic() + 5
    while snapshot()['execution']['current_line'] != 7 and time.monotonic() < deadline:
        time.sleep(.02)
    assert snapshot()['execution']['current_line'] == 7
    assert [e['payload']['message'] for e in snapshot()['logs']] == ['inner', 'after']
    assert not any(row['bound_command_id'] for row in service.list_breakpoints(execution.id))
    command('STEP')
    final = wait_for_state(client, execution.id, viewer_headers, {'completed'})
    assert final['execution']['variables']['python_completed'] is True
    assert [e['payload']['message'] for e in final['logs']] == ['inner', 'after', 'done']


def test_abort_can_interrupt_step_over_in_a_long_library_call(client, operator_headers, viewer_headers, runtime_configuration):
    supervisor = client.app.state.supervisor
    supervisor.python_runtime_configuration = runtime_configuration
    source = HEADER+'import time\ndef f():\n time.sleep(20)\n print("must not run")\nf()\nprint("done")\n'
    procedure = client.app.state.catalog.validate_source(source, 'python_slow_step.py')
    execution = supervisor.create_execution(procedure, actor='pytest-operator', role='operator',
        reason='interrupt long step', idempotency_key='python-slow-step', automatic=True)
    command, _ = python_controls(client, operator_headers, viewer_headers, execution.id)
    command('RUN', {'line': 6, 'source_digest': execution.procedure_hash})
    wait_for_state(client, execution.id, viewer_headers, {'paused'})
    command('STEP_OVER')
    wait_for_state(client, execution.id, viewer_headers, {'running'})
    command('ABORT')
    final = wait_for_state(client, execution.id, viewer_headers, {'aborted'})
    assert final['logs'] == [] and final['execution']['current_step'] == 0


def test_worker_loss_at_a_breakpoint_cancels_without_running_the_line(runtime_configuration):
    client = job(runtime_configuration, HEADER+'print("must not run")\n', start_paused=True)
    try:
        wait(client, {'PAUSED'})
        time.sleep(3.5)
        result = wait(client)
        assert result['state'] == 'ABORTED' and result['error_code'] == 'PYTHON_WORKER_LOST'
        assert result['stdout'] == ''
    finally:
        client.close()


def test_descendants_that_leave_the_process_group_are_cleaned_up(runtime_configuration):
    source = HEADER+'''import subprocess, sys, time
subprocess.Popen([sys.executable, '-c', 'import time; print("descendant", flush=True); time.sleep(100)'], start_new_session=True)
time.sleep(.3)
print('parent done')
'''
    client = job(runtime_configuration, source)
    started = time.monotonic()
    try:
        result = wait(client)
        assert result['state'] == 'COMPLETED' and 'parent done' in result['stdout'], result
        assert time.monotonic()-started < 3
    finally: client.close()


@pytest.mark.parametrize('state,actions', [('running', {'pause','stop','abort'}), ('paused', {'run','step','step_over','stop','abort'}),
                                         ('completed', set()), ('recovery_required', {'stop','abort'})])
def test_python_operator_controls_do_not_advertise_navigation_or_replay(state, actions):
    execution = Execution(id='python-actions', procedure_id='python', procedure_name='Python', procedure_hash='a'*64,
        ir_version=IR_VERSION, context_id='simulator', state=state, steps=[], variables={}, next_sequence=1)
    assert set(execution_dict(execution)['allowed_actions']) == actions
    assert execution_dict(execution)['source_controls'] == {'breakpoints': True, 'run_to_line': True, 'executable_lines': []}


@pytest.mark.parametrize('terminal_action', ['ABORT', 'STOP'])
def test_python_executor_controls_are_fenced_and_operate_on_the_process(client, operator_headers, viewer_headers, runtime_configuration, terminal_action):
    supervisor = client.app.state.supervisor
    supervisor.python_runtime_configuration = runtime_configuration
    source = HEADER+'import time\nfor i in range(200):\n print(i, flush=True); time.sleep(.05)'
    procedure = client.app.state.catalog.validate_source(source, 'python_controls.py')
    execution = supervisor.create_execution(procedure, actor='pytest-operator', role='operator', reason='Python process control',
                                            idempotency_key='python-process-controls', automatic=True)
    snapshot = wait_for_state(client, execution.id, viewer_headers, {'paused'})
    headers, lease = _acquire_control(client, operator_headers, execution.id, snapshot, 'python')
    proof = _proof(headers, lease); proof['controller_lease_id'] = proof.pop('lease_id')
    service = client.app.state.operator_service
    breakpoint_proof = {**proof, 'lease_id': proof['controller_lease_id']}
    breakpoint_proof.pop('controller_lease_id')
    for line in (1, 6):
        with pytest.raises(OperatorValidationError, match='not executable'):
            service.put_breakpoint(execution.id, line, one_shot=False,
                expected_execution_revision=supervisor.get_execution(execution.id).revision,
                idempotency_key=f'python-forbidden-breakpoint-{line}', reason='no native line control',
                **breakpoint_proof)
    assert service.list_breakpoints(execution.id) == []
    def command_state(command_id):
        with client.app.state.session_factory() as session:
            return session.get(OperatorCommand, command_id).state
    for unsupported in ('SKIP', 'GOTO', 'RECOVER', 'RELOAD', 'BACKGROUND'):
        with pytest.raises(OperatorValidationError, match='PYTHON_COMMAND_UNSUPPORTED'):
            service.accept_operator_command(execution.id, unsupported, supervisor.get_execution(execution.id).revision,
                idempotency_key='python-forbidden-'+unsupported, role='operator', reason='no unsupported control',
                target={'line': 1} if unsupported == 'GOTO' else {}, **proof)
    with pytest.raises(OperatorAuthorizationError, match='fencing'):
        service.accept_operator_command(execution.id, 'PAUSE', supervisor.get_execution(execution.id).revision,
            idempotency_key='python-stale-fence', role='operator', reason='reject stale control', target={},
            **{**proof, 'control_fencing_token': proof['control_fencing_token']+1})
    for action, state in [('RUN', 'running'), ('PAUSE', 'paused'), ('RUN', 'running'), (terminal_action, 'aborted')]:
        command = service.accept_operator_command(execution.id, action, supervisor.get_execution(execution.id).revision,
            idempotency_key=str(uuid.uuid4()), role='operator', reason='Python process control', target={}, **proof)
        supervisor.dispatch_operator_command(command)
        wait_for_state(client, execution.id, viewer_headers, {state}, timeout=8)
        deadline = time.monotonic()+3
        while time.monotonic() < deadline and command_state(command['id']) != 'SETTLED':
            time.sleep(.02)
        assert command_state(command['id']) == 'SETTLED'
        if action == 'PAUSE':
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                snapshot = client.get(f'/api/v1/executions/{execution.id}/snapshot', headers=viewer_headers).json()
                if snapshot['execution']['current_line'] is None:
                    break
                time.sleep(.02)
            assert snapshot['execution']['current_line'] is None  # Signal pause has no exact line boundary.
    assert supervisor.get_execution(execution.id).current_step == 0


def test_executor_retains_failure_output_without_advancing_checkpoint(client, operator_headers, viewer_headers, runtime_configuration):
    supervisor = client.app.state.supervisor
    supervisor.python_runtime_configuration = runtime_configuration
    source = HEADER+'print("before failure"); raise AssertionError("visible failure")'
    procedure = client.app.state.catalog.validate_source(source, 'python_failure.py')
    execution = supervisor.create_execution(procedure, actor='pytest-operator', role='operator', reason='Python failure',
                                            idempotency_key='python-failure', automatic=True)
    command, _ = python_controls(client, operator_headers, viewer_headers, execution.id)
    command('RUN')
    snapshot = wait_for_state(client, execution.id, viewer_headers, {'failed'})
    assert snapshot['execution']['current_step'] == 0 and snapshot['execution']['variables'] == {}
    events = client.get(f'/api/v1/executions/{execution.id}/events?limit=1000', headers=viewer_headers).json()['items']
    messages = [e['payload'] for e in events if e['event_type'] == 'procedure.log']
    assert any(e['message'] == 'before failure' and e['stream'] == 'stdout' for e in messages)
    assert any('visible failure' in e['message'] and e['stream'] == 'stderr' for e in messages)
    [result] = [e['payload'] for e in events if e['event_type'] == 'procedure.python_result']
    assert result['state'] == 'FAILED' and result['exit_code'] == 1


def test_large_python_output_waits_for_durable_consumer_before_worker_exit(client, operator_headers, viewer_headers, runtime_configuration, monkeypatch):
    supervisor = client.app.state.supervisor
    supervisor.python_runtime_configuration = runtime_configuration
    original = supervisor.append_event
    def slow_append(execution_id, event_type, *args, **kwargs):
        if event_type == 'procedure.log':
            time.sleep(.015)
        return original(execution_id, event_type, *args, **kwargs)
    monkeypatch.setattr(supervisor, 'append_event', slow_append)
    source = HEADER+'for i in range(345): print(i)'
    procedure = client.app.state.catalog.validate_source(source, 'python_output.py')
    execution = supervisor.create_execution(procedure, actor='pytest-operator', role='operator', reason='slow output persistence',
                                            idempotency_key='python-output', automatic=True)
    command, _ = python_controls(client, operator_headers, viewer_headers, execution.id)
    command('RUN')
    snapshot = wait_for_state(client, execution.id, viewer_headers, {'completed', 'recovery_required', 'failed'}, timeout=20)
    assert snapshot['execution']['state'] == 'completed'
    assert snapshot['execution']['variables']['python_stdout_lines'] == 345
    events = client.get(f'/api/v1/executions/{execution.id}/events?limit=1000', headers=viewer_headers).json()['items']
    logs = [e['payload']['message'] for e in events if e['event_type'] == 'procedure.log']
    assert logs == [str(i) for i in range(345)]
    assert not any(e['event_type'] in {'worker.crashed','worker.consumer_failed'} for e in events)
