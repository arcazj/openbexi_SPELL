"""The release recorder must demand independently validated DSS evidence."""
from __future__ import annotations

import json
import threading
import pytest

from scripts import release_next as release


def test_gate_rejects_renewal_failure_that_finishes_after_validation(tmp_path, monkeypatch):
    from scripts import qualify_next as qualifier
    token = tmp_path / "operator.token"
    pending = token.with_suffix(".pending")
    started, finish = threading.Event(), threading.Event()
    calls = []
    real_thread = threading.Thread
    class JoinSettlesRenewal(real_thread):
        def join(self, timeout=None):
            # Validation has returned while renewal is still in flight.
            assert started.is_set()
            finish.set()
            super().join(timeout)
    monkeypatch.setattr(qualifier.threading, "Thread", JoinSettlesRenewal)
    def renew():
        calls.append(1)
        if len(calls) == 1:
            token.write_bytes(b"private-parent-credential")
            return
        pending.write_bytes(b"incomplete-renewal")
        started.set()
        assert finish.wait(2)
        raise RuntimeError("issuer became unavailable")
    with pytest.raises(ValueError, match="DSS credential renewal failed"):
        with qualifier.renewing_credential(renew, token, interval=0):
            assert started.wait(2)
    assert len(calls) == 2
    assert not token.exists() and not pending.exists()


@pytest.mark.parametrize("failure", ["issuer", "validation", None])
def test_gate_always_removes_parent_credential(tmp_path, failure):
    from scripts import qualify_next as qualifier
    token = tmp_path / "operator.token"
    pending = token.with_suffix(".pending")
    def renew():
        token.write_bytes(b"private-parent-credential")
        pending.write_bytes(b"incomplete-renewal")
        if failure == "issuer":
            raise RuntimeError("issuer unavailable")
    def validate():
        with qualifier.renewing_credential(renew, token):
            if failure == "validation":
                raise RuntimeError("required case failed")
    if failure:
        with pytest.raises(RuntimeError):
            validate()
    else:
        validate()
    assert not token.exists() and not pending.exists()


@pytest.mark.parametrize("minor,expected", [(18, {"backend", "driver", "frontend", "proxy"}),
    (19, {"backend", "driver", "frontend", "proxy", "dss", "kafka"})])
def test_release_image_inventory_includes_shared_simulator(monkeypatch, minor, expected):
    monkeypatch.setattr(release, "MINOR", minor)
    assert release.image_names() == expected


def test_dss_report_is_mandatory_even_if_all_unit_tests_pass(tmp_path):
    with pytest.raises(FileNotFoundError):
        release.verify_dss_capture(tmp_path, source_commit="a" * 40, image_ids={})


def test_dss_recorder_passes_external_source_and_image_bindings(tmp_path, monkeypatch):
    from scripts import validate_dss_delivery as validator
    source = "a" * 40
    images = {name: "sha256:" + str(index) * 64 for index, name in enumerate(sorted(release.image_names()), 1)}
    report = {"decision": "PASS", "source_commit": "untrusted-reported-source"}
    (tmp_path / "dss-validation.json").write_text(json.dumps(report))
    (tmp_path / "dss-bindings.json").write_text(json.dumps({"source_commit":source,"image_ids":images}))
    calls = []
    def validate(data, **bindings):
        calls.append((data, bindings))
        if bindings["source_commit"] != source or bindings["image_ids"] != images:
            raise ValueError("external bindings differ")
    monkeypatch.setattr(validator, "validate_report", validate)
    assert release.verify_dss_capture(tmp_path, source_commit=source, image_ids=images) == report
    assert calls == [(report, {"source_commit": source, "image_ids": images, "root": release.ROOT,
                              "capture_root": tmp_path / "dss-validation-captures"})]
    with pytest.raises(ValueError, match="producer bindings differ"):
        release.verify_dss_capture(tmp_path, source_commit="b" * 40, image_ids=images)


def test_dss_validator_rejection_cannot_be_replaced_by_reported_pass(tmp_path, monkeypatch):
    from scripts import validate_dss_delivery as validator
    (tmp_path / "dss-validation.json").write_text('{"decision":"PASS"}')
    (tmp_path / "dss-bindings.json").write_text(json.dumps({"source_commit":"a"*40,"image_ids":{}}))
    def reject(*args, **kwargs):
        raise ValueError("missing case: procedure:unexecuted")
    monkeypatch.setattr(validator, "validate_report", reject)
    with pytest.raises(ValueError, match="missing case"):
        release.verify_dss_capture(tmp_path, source_commit="a" * 40, image_ids={})


@pytest.mark.parametrize("mutation", ["source", "images", "extra"])
def test_contradictory_producer_sidecar_blocks_dss_acceptance(tmp_path, monkeypatch, mutation):
    from scripts import validate_dss_delivery as validator
    source="a"*40
    images={name:"sha256:"+str(index)*64 for index,name in enumerate(sorted(release.image_names()),1)}
    bindings={"source_commit":source,"image_ids":images.copy()}
    if mutation=="source":bindings["source_commit"]="b"*40
    elif mutation=="images":bindings["image_ids"]["dss"]="sha256:"+"f"*64
    else:bindings["unbound_extra"]=True
    (tmp_path/"dss-validation.json").write_text('{"decision":"PASS"}')
    (tmp_path/"dss-bindings.json").write_text(json.dumps(bindings))
    monkeypatch.setattr(validator,"validate_report",lambda *args,**kwargs:None)
    with pytest.raises(ValueError,match="producer bindings differ"):
        release.verify_dss_capture(tmp_path,source_commit=source,image_ids=images)


def test_kafka_recipe_matches_lock_and_removes_old_layers():
    from scripts.generate_kafka_security_dockerfile import generated
    recipe = generated()
    assert recipe == (release.ROOT / "dss/kafka.Dockerfile").read_bytes()
    assert b"FROM scratch\nCOPY --from=secured-runtime / /" in recipe
    assert recipe.count(b"ADD --checksum=sha256:") == 25


@pytest.mark.parametrize("mutation", ["coordinate", "origin", "checksum", "missing"])
def test_kafka_recipe_rejects_unbound_dependency_inputs(tmp_path, mutation):
    from scripts.generate_kafka_security_dockerfile import generated
    lock = json.loads((release.ROOT / "contracts/dss/kafka_dependency_lock.json").read_bytes())
    if mutation == "coordinate":
        lock["artifacts"][0]["name"] = "libcrypto3;untrusted"
    elif mutation == "origin":
        lock["artifacts"][0]["url"] = lock["artifacts"][0]["url"].replace("dl-cdn.alpinelinux.org", "example.org")
    elif mutation == "checksum":
        lock["artifacts"][0]["sha256"] = "not-a-digest"
    else:
        lock["artifacts"].pop()
    folder = tmp_path / "contracts/dss"
    folder.mkdir(parents=True)
    (folder / "kafka_dependency_lock.json").write_text(json.dumps(lock))
    with pytest.raises(ValueError):
        generated(tmp_path)


@pytest.mark.parametrize("mutation", [None, "jar_bytes", "jar_size", "old_classpath", "apk_version", "lock_bytes"])
def test_kafka_installed_inventory_verifies_actual_dependency_bytes(mutation):
    import hashlib
    from scripts.kafka_security_inventory import LOCK_PATH, verify_inventory
    raw = (release.ROOT / "contracts/dss/kafka_dependency_lock.json").read_bytes()
    lock = json.loads(raw)
    hashes = {LOCK_PATH: hashlib.sha256(raw).hexdigest()}
    sizes = {}
    installed = []
    for row in lock["artifacts"]:
        if row["kind"] == "APK":
            installed.append(row["name"] + "-" + row["version"])
        else:
            path = "/opt/kafka/libs/" + row["url"].rsplit("/", 1)[-1]
            hashes[path] = row["sha256"]
            sizes[path] = row["size"]
    files = list(sizes)
    if mutation == "jar_bytes":
        hashes[files[0]] = "0" * 64
    elif mutation == "jar_size":
        sizes[files[0]] += 1
    elif mutation == "old_classpath":
        files.append("/opt/kafka/libs/jackson-core-2.21.2.jar")
    elif mutation == "apk_version":
        installed[0] = "libcrypto3-3.5.7-r0"
    elif mutation == "lock_bytes":
        hashes[LOCK_PATH] = "0" * 64
    if mutation:
        with pytest.raises(ValueError):
            verify_inventory(raw, hashes=hashes, sizes=sizes, installed_apks=installed, jar_files=files)
    else:
        assert verify_inventory(raw, hashes=hashes, sizes=sizes, installed_apks=installed, jar_files=files)["decision"] == "PASS"
