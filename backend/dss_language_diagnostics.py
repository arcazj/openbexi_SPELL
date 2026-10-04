"""Bounded metadata retained when a closed DSS case fails before settlement."""
from .dss_language_broker import canonical

MAX_ITEMS = 22
MAX_RESULTS = 8
MAX_STRING = 160
MAX_BYTES = 32768
SAMPLE_FIELDS = (
    "item_id", "sample_id", "observation_id", "source_id", "source_epoch", "source_sequence",
    "projection_sequence", "projection_time", "acquired_at_unix_ns", "received_at_unix_ns",
    "received_at", "source", "clock_provenance", "clock_uncertainty_ns", "validity", "quality",
    "freshness", "freshness_policy_revision", "synchronization_state", "declared_scalar_type",
    "observed_scalar_type", "mode", "field",
)
CLOCK_FIELDS = ("source_epoch", "source_sequence", "source_packet_sha256", "database_digest",
                "time_unix_ns", "uncertainty_ns", "provenance")


def metadata(value, fields):
    if type(value) is not dict:
        return None
    result = {}
    for key in fields:
        if key not in value:
            continue
        scalar = value[key]
        if scalar is None or type(scalar) is bool:
            result[key] = scalar
        elif type(scalar) is int and -(2**63) <= scalar < 2**64:
            result[key] = scalar
        elif type(scalar) is str:
            result[key] = scalar[:MAX_STRING]
        else:
            result[key] = "INVALID_METADATA_TYPE"
    return result


def readiness(snapshot, state, observed_at_unix_ns):
    items = snapshot.get("items", [])
    if type(items) is not list:
        raise ValueError("readiness items are malformed")
    return {"observed_at_unix_ns":str(observed_at_unix_ns), "expected_epoch":str(state["epoch"])[:MAX_STRING],
        "through_sequence":metadata(snapshot, ("through_sequence", "snapshot_at_database_time")),
        "clock_present":"driver_time" in snapshot,
        "clock":metadata(snapshot.get("driver_time"), CLOCK_FIELDS),
        "item_count":len(items), "items":[sample_metadata(row,observed_at_unix_ns) for row in items[:MAX_ITEMS]]}


def sample_metadata(value, observed_at_unix_ns):
    result=metadata(value,SAMPLE_FIELDS)
    if result is None:
        return None
    acquired=result.get("acquired_at_unix_ns")
    if (type(acquired) is str and 1<=len(acquired)<=19 and acquired.isascii() and acquired.isdecimal()
            and str(int(acquired))==acquired and 0<int(acquired)<2**63):
        result["age_at_diagnostic_ns"]=str(observed_at_unix_ns-int(acquired))
    return result


def observation(request, result, started_at_unix_ns, resolved_at_unix_ns):
    return {"request":metadata(request,("request_id", "operation", "step_index")),
        "result":metadata(result,("outcome", "error_code")),
        "evidence":sample_metadata(result.get("evidence"),resolved_at_unix_ns),
        "started_at_unix_ns":str(started_at_unix_ns), "resolved_at_unix_ns":str(resolved_at_unix_ns)}


def failure(executor):
    rows = getattr(executor,"observation_diagnostics", [])
    if type(rows) is not list:
        raise ValueError("observation diagnostics are malformed")
    capture = getattr(executor,"worker_capture", None)
    result = {"schema_version":"openbexi.dss.language-failure/1",
        "readiness":getattr(executor,"readiness_capture", None),
        "worker":metadata(capture,("execution_id", "source_sha256", "ir_version")),
        "observation_count":getattr(executor,"observation_diagnostic_count",len(rows)),
        "observations":rows[:MAX_RESULTS]}
    if len(canonical(result)) > MAX_BYTES:
        raise ValueError("failure diagnostic exceeds its byte bound")
    return result
