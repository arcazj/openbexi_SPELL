"""Exercise Docker DNS replacement through the actual shipped Nginx binary."""
from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tomllib
import uuid

import pytest


ROOT = Path(__file__).resolve().parents[2]
QUALIFIER_IMAGE = "openbexi-spell-qualification:next"
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
PROXY_IMAGE = f"openbexi-spell-proxy:v{VERSION}"

# Deliberately tiny, deterministic peers. They expose the exact URI/headers and
# a real RFC 6455 text exchange; they do not simulate application authorization.
UPSTREAM = r'''
import base64, hashlib, json, struct, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port, identity = int(sys.argv[1]), sys.argv[2]
class Handler(BaseHTTPRequestHandler):
 protocol_version = 'HTTP/1.1'
 def log_message(self, *args): pass
 def serve(self):
  value = {'identity':identity, 'path':self.path, 'method':self.command,
   'host':self.headers.get('Host'), 'ingress':self.headers.get('X-Spell-Local-Ingress'),
   'forwarded_for':self.headers.get('X-Forwarded-For'),
   'protocol':self.headers.get('Sec-WebSocket-Protocol')}
  if self.headers.get('Upgrade', '').lower() == 'websocket':
   key = self.headers['Sec-WebSocket-Key']
   accept = base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
   self.send_response(101); self.send_header('Upgrade','websocket'); self.send_header('Connection','Upgrade')
   self.send_header('Sec-WebSocket-Accept',accept); self.send_header('Sec-WebSocket-Protocol','spell-regression')
   self.end_headers()
   head=self.rfile.read(2)
   assert len(head)==2 and head[0]==0x81 and head[1]&0x80
   length=head[1]&127; assert length<126
   mask=self.rfile.read(4); raw=self.rfile.read(length); assert len(raw)==length
   value['text']=bytes(v^mask[i%4] for i,v in enumerate(raw)).decode()
   data=json.dumps(value,sort_keys=True).encode()
   prefix=bytes((0x81,len(data))) if len(data)<126 else bytes((0x81,126))+struct.pack('!H',len(data))
   self.wfile.write(prefix+data); self.wfile.flush(); self.close_connection=True
  else:
   count=int(self.headers.get('Content-Length','0')); assert count<=65536
   value['body']=self.rfile.read(count).decode()
   data=json.dumps(value,sort_keys=True).encode()
   self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data)))
   self.end_headers(); self.wfile.write(data)
 do_GET=serve
 do_POST=serve
ThreadingHTTPServer(('0.0.0.0',port),Handler).serve_forever()
'''


CLIENT = r'''
import base64, hashlib, http.client, json, os, socket, struct, sys, time
spec=json.loads(sys.argv[1])
def request(path, *, host='attacker.invalid', origin=None, body=None):
 c=http.client.HTTPConnection('proxy',8080,timeout=1)
 headers={'Host':host,'X-Spell-Local-Ingress':'forged','X-Forwarded-For':'203.0.113.9'}
 if origin is not None: headers['Origin']=origin
 if body is not None: headers['Content-Type']='application/json'
 try:
  c.request('POST' if body is not None else 'GET',path,body=body,headers=headers)
  r=c.getresponse(); raw=r.read(); status=r.status; h=dict(r.getheaders())
  assert h.get('X-Content-Type-Options')=='nosniff' and h.get('X-Frame-Options')=='DENY'
  assert h.get('Referrer-Policy')=='no-referrer' and "frame-ancestors 'none'" in h.get('Content-Security-Policy','')
  return status,json.loads(raw) if status==200 else None
 finally: c.close()
def recovered(path, expected):
 began=time.monotonic(); last=None
 while time.monotonic()-began<5:
  try:
   status,body=request(path); last={'status':status,'identity':body.get('identity') if body else None}
   if status==200 and body['identity']==expected: return body,time.monotonic()-began
  except (OSError,http.client.HTTPException) as e: last=type(e).__name__
  time.sleep(.05)
 raise AssertionError('Nginx DNS recovery exceeded five seconds: '+str(last))
def websocket(expected):
 path='/api/ws/executions/test%2Fid?after=7&cursor=a%2Fb'; key=base64.b64encode(os.urandom(16)).decode()
 with socket.create_connection(('proxy',8080),timeout=1) as sock:
  sock.settimeout(1)
  sock.sendall(('GET '+path+' HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: '+key+'\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: spell-regression\r\nX-Spell-Local-Ingress: forged\r\n\r\n').encode())
  stream=sock.makefile('rb'); assert stream.readline().split()[1]==b'101'
  headers={}
  while True:
   line=stream.readline()
   if line==b'\r\n':break
   assert line; name,value=line.decode().split(':',1);headers[name.lower()]=value.strip()
  assert headers['upgrade'].lower()=='websocket' and headers['connection'].lower()=='upgrade'
  assert headers['sec-websocket-protocol']=='spell-regression'
  assert headers['sec-websocket-accept']==base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
  payload=b'exact binary-framed text';mask=os.urandom(4)
  sock.sendall(bytes((0x81,0x80|len(payload)))+mask+bytes(v^mask[i%4] for i,v in enumerate(payload)))
  head=stream.read(2);assert len(head)==2 and head[0]==0x81 and not head[1]&0x80
  count=head[1]&127
  if count==126:count=struct.unpack('!H',stream.read(2))[0]
  assert count<4096
  value=json.loads(stream.read(count));assert value['identity']==expected and value['path']==path
  assert value['host']=='127.0.0.1' and value['ingress'] is None and value['protocol']=='spell-regression'
  assert value['text']==payload.decode();stream.close()
api='/api/v1/probe/a%2Fb?x=one%2Ftwo&x=2'
dss='/dss/api/v1/evidence?scenario_id=alpha%2Fbeta&offset=0&limit=32'
first=time.monotonic();api_body,api_seconds=recovered(api,spec['backend'])
assert api_body['path']==api and api_body['host']=='127.0.0.1' and api_body['ingress'] is None
assert api_body['forwarded_for'] not in (None,'203.0.113.9')
dss_body,dss_seconds=recovered(dss,spec['dss'])
assert dss_body['path']==dss.removeprefix('/dss') and dss_body['host']=='dss'
status,local=request('/api/v1/local-session',host='127.0.0.1:8080',origin='http://127.0.0.1:8080',body='{}')
assert status==200 and local['identity']==spec['backend'] and local['body']=='{}'
assert local['path']=='/api/v1/local-session' and local['host']=='127.0.0.1:8080' and local['ingress']=='loopback-proxy-v16'
for host,origin in [('127.0.0.1:8080','https://evil.invalid'),('evil.invalid','http://evil.invalid')]:
 assert request('/api/v1/local-session',host=host,origin=origin,body='{}')[0]==403
assert request('/api/v1/local-session',host='127.0.0.1:8080',origin='http://127.0.0.1:8080',body='x'*33)[0]==413
websocket(spec['backend'])
print(json.dumps({'backend':spec['backend'],'dss':spec['dss'],'api_recovery_seconds':api_seconds,
 'dss_recovery_seconds':dss_seconds,'total_seconds':time.monotonic()-first,'websocket':'PASS','local_boundary':'PASS'}))
'''


def _docker(*args: str, data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(["docker", *args], input=data, capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise AssertionError(f"isolated Docker {args[0]} exceeded 30 seconds") from None
    if result.returncode:
        # The fixture contains only public dummy peers. Retain bounded actual
        # oracle stderr, without printing the large inline program/command.
        stderr = result.stderr.decode("utf-8", errors="replace")[-1800:]
        stdout = result.stdout.decode("utf-8", errors="replace")[-600:]
        raise AssertionError(f"isolated Docker {args[0]} failed ({result.returncode}); stderr={stderr!r}; stdout={stdout!r}")
    return result


def _inspect(container: str) -> dict:
    return json.loads(_docker("inspect", container).stdout)[0]


def _copy_configuration(container: str, configuration: bytes) -> None:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for name, content in (("nginx.conf", configuration), ("security_headers.conf", (ROOT / "proxy/security_headers.conf").read_bytes())):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.uid, info.gid = len(content), 0o644, 0, 0
            tar.addfile(info, io.BytesIO(content))
    _docker("cp", "-", f"{container}:/etc/nginx/", data=archive.getvalue())


def _container_file(container: str, path: str) -> bytes:
    raw = _docker("cp", f"{container}:{path}", "-").stdout
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        entries = tar.getmembers()
        assert len(entries) == 1 and entries[0].isfile()
        stream = tar.extractfile(entries[0])
        assert stream is not None
        return stream.read()


def _unused_subnet() -> str:
    ids = _docker("network", "ls", "--quiet").stdout.decode().split()
    networks = json.loads(_docker("network", "inspect", *ids).stdout) if ids else []
    occupied = [ipaddress.ip_network(config["Subnet"]) for network in networks
                for config in (network["IPAM"].get("Config") or []) if config.get("Subnet")]
    start = int(uuid.uuid4().hex[:4], 16)
    for offset in range(65536):
        number = (start + offset) % 65536
        candidate = ipaddress.ip_network(f"10.{number // 256}.{number % 256}.0/24")
        if not any(other.version == 4 and candidate.overlaps(other) for other in occupied):
            return str(candidate)
    raise AssertionError("no nonoverlapping isolated regression subnet")


def exercise_dns_replacement(configuration: bytes, *, require_image_config: bool = True) -> dict:
    """Also usable for a retained old-config negative proof, without live services."""
    assert shutil.which("docker"), "enabled Nginx regression requires Docker"
    images = {name: _docker("image", "inspect", "--format", "{{.Id}}", image).stdout.decode().strip()
              for name, image in (("proxy", PROXY_IMAGE), ("python", QUALIFIER_IMAGE))}
    assert all(value.startswith("sha256:") and len(value) == 71 for value in images.values())
    prefix = "spell-dns-regression-" + uuid.uuid4().hex[:12]
    network = prefix + "-net"
    print("Isolated Nginx fixture:", prefix)
    containers: list[str] = []
    created_network = False
    def create(name: str, image: str, args: list[str], *, alias: str | None = None, ip: str | None = None) -> str:
        container = prefix + "-" + name
        options = ["create", "--name", container, "--network", network, "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges:true", "--pids-limit", "32", "--memory", "64m", "--cpus", "0.25"]
        if alias: options += ["--network-alias", alias]
        if ip: options += ["--ip", ip]
        options += ["--entrypoint", args[0], image, *args[1:]]
        _docker(*options)
        containers.append(container)
        return container
    def server(name: str, alias: str | None, port: int, *, ip: str | None = None) -> str:
        container = create(name, images["python"], ["python", "-u", "-c", UPSTREAM, str(port), name], alias=alias, ip=ip)
        _docker("start", container)
        return container
    def address(container: str) -> str:
        return _inspect(container)["NetworkSettings"]["Networks"][network]["IPAddress"]
    def probe(backend: str, dss: str) -> dict:
        result = _docker("exec", client, "python", "-c", CLIENT, json.dumps({"backend": backend, "dss": dss}))
        return json.loads(result.stdout)
    try:
        _docker("network", "create", "--internal", "--subnet", _unused_subnet(), network)
        created_network = True
        backend = server("backend-a", "backend", 8000)
        dss = server("dss-a", "dss", 8081)
        client = create("client", images["python"], ["python", "-c", "import time; time.sleep(300)"])
        _docker("start", client)
        proxy = create("proxy", images["proxy"], ["nginx", "-g", "daemon off;"], alias="proxy")
        image_configuration = _container_file(proxy, "/etc/nginx/nginx.conf")
        if require_image_config:
            # Canonical proof must exercise the prepared image unchanged.
            assert image_configuration == configuration, "prepared proxy image configuration differs from frozen source"
            assert _container_file(proxy, "/etc/nginx/security_headers.conf") == (ROOT / "proxy/security_headers.conf").read_bytes()
        else:
            # Only the separate diagnostic old-config negative proof overrides
            # a stopped fixture container; the registered test never does this.
            _copy_configuration(proxy, configuration)
        _docker("start", proxy)
        before = _inspect(proxy)
        initial = probe("backend-a", "dss-a")
        workers = _docker("exec", proxy, "cat", "/proc/1/task/1/children").stdout.split()
        assert workers
        changes = []
        for name, old, port in (("backend", backend, 8000), ("dss", dss, 8081)):
            old_ip = address(old)
            _docker("rm", "--force", old)
            containers.remove(old)
            # Retain a responsive canary at the old address: old static DNS must
            # actually fail the identity oracle, even if connection succeeds.
            server(name + "-old-ip-canary", None, port, ip=old_ip)
            replacement = server(name + "-b", name, port)
            new_ip = address(replacement)
            assert new_ip != old_ip
            observed = probe("backend-b", "dss-a" if name == "backend" else "dss-b")
            assert observed["api_recovery_seconds"] <= 5 and observed["dss_recovery_seconds"] <= 5
            changes.append({"alias": name, "old_ip": old_ip, "new_ip": new_ip, **observed})
        after = _inspect(proxy)
        assert before["Id"] == after["Id"] and before["State"]["Pid"] == after["State"]["Pid"]
        assert before["State"]["StartedAt"] == after["State"]["StartedAt"] and after["RestartCount"] == 0
        assert after["State"]["Running"] is True
        assert _docker("exec", proxy, "cat", "/proc/1/task/1/children").stdout.split() == workers
        actual = _docker("exec", proxy, "cat", "/etc/nginx/nginx.conf").stdout
        assert actual == configuration
        return {"images": images, "configuration_sha256": hashlib.sha256(configuration).hexdigest(),
                "image_configuration_matches_source": image_configuration == configuration,
                "proxy_id": after["Id"], "proxy_started_at": after["State"]["StartedAt"], "initial": initial, "replacements": changes}
    finally:
        primary = sys.exception()
        cleanup_errors = []
        for container in reversed(containers):
            try:
                _docker("rm", "--force", container)
            except Exception as error:
                cleanup_errors.append(f"{container}: {str(error)[:600]}")
        if created_network:
            try:
                _docker("network", "rm", network)
            except Exception as error:
                cleanup_errors.append(f"{network}: {str(error)[:600]}")
        if cleanup_errors:
            raise AssertionError("Isolated Nginx cleanup did not complete: " + "; ".join(cleanup_errors)) from primary


@pytest.mark.skipif(os.environ.get("SPELL_RUN_COMPOSE_RUNTIME_TESTS") != "1", reason="requires the isolated Docker Nginx runtime gate")
def test_actual_nginx_recovers_backend_and_dss_dns_replacement_without_restart(record_property) -> None:
    evidence = exercise_dns_replacement((ROOT / "proxy/nginx.conf").read_bytes())
    record_property("nginx_dns_replacement", json.dumps(evidence, sort_keys=True))
