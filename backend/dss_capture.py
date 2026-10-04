"""Drain bounded immutable-revision DSS evidence pages without dropping any record."""
from urllib.parse import quote
from urllib.error import HTTPError
import time
from .dss_language_broker import canonical


def set_running(call, running, *, epoch=None):
    """Fenced lifecycle control; retry only a rejected, unapplied revision race."""
    if type(running) is not bool:
        raise ValueError("DSS execution control must be Boolean")
    for attempt in range(4):
        state=call("/state")
        if epoch is not None and state["epoch"]!=epoch:
            raise ValueError("DSS execution control crossed its scenario epoch")
        if state["running"] is running:
            return state
        try:
            changed=call("/control",{"action":"RESUME" if running else "PAUSE",
                "expected_epoch":state["epoch"],"expected_revision":state["revision"]})
        except HTTPError as exc:
            if exc.code!=409 or attempt==3:raise
            continue
        if changed["epoch"]!=state["epoch"] or changed["running"] is not running:
            raise ValueError("DSS execution control returned another state")
        return changed
    raise ValueError("DSS execution control revision did not stabilize")


def collect_evidence(call, scenario_id, *, conflict_retries=0):
    """Retry only HTTP revision conflicts; never repeat a source or command."""
    if type(conflict_retries) is not int or not 0 <= conflict_retries <= 3:
        raise ValueError("DSS evidence retry bound differs")
    for attempt in range(conflict_retries + 1):
        try:
            return _collect_evidence(call, scenario_id)
        except HTTPError as exc:
            if exc.code != 409 or attempt == conflict_retries:
                raise
            time.sleep(0.05)


def _collect_evidence(call, scenario_id):
    path = "/evidence?scenario_id=" + quote(scenario_id, safe="") + "&limit=32"
    first = call(path + "&offset=0")
    pagination = first.get("pagination")
    if type(pagination) is not dict:
        raise ValueError("DSS evidence does not provide bounded pagination")
    metadata = {key:value for key,value in first.items() if key not in {"commands", "operations", "packets", "pagination"}}
    output = {**metadata, "commands":[], "operations":[], "packets":[]}
    page, offset = first, 0
    counts, revision = pagination["counts"], pagination["revision"]
    if (set(counts) != {"commands", "operations", "packets"}
            or any(type(value) is not int or not 0 <= value <= 20000 for value in counts.values())):
        raise ValueError("DSS scenario record count exceeds its bound")
    for _ in range(626):
        meta = {key:value for key,value in page.items() if key not in {"commands", "operations", "packets", "pagination"}}
        current = page["pagination"]
        if (canonical(meta) != canonical(metadata) or current["counts"] != counts
                or current["revision"] != revision or current["offset"] != offset or current["limit"] != 32):
            raise ValueError("DSS scenario changed during evidence export")
        for key in counts:
            if len(page[key]) != min(32, max(0, counts[key] - offset)):
                raise ValueError("DSS evidence page omits records")
            output[key].extend(page[key])
        following = current["next_offset"]
        if following is None:
            if any(len(output[key]) != counts[key] for key in counts):
                raise ValueError("DSS evidence export is incomplete")
            return output
        if type(following) is not int or following != offset + 32:
            raise ValueError("DSS evidence page cursor differs")
        offset = following
        page = call(path + f"&offset={offset}&expected_revision={revision}")
    raise ValueError("DSS evidence page bound exceeded")
