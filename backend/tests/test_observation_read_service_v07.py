from __future__ import annotations

from backend.observation_read_service import ObservationReadService


def service_identity(service: ObservationReadService) -> tuple[str, str]:
    identity = service.identity()
    return identity["catalog_id"], identity["catalog_digest"]


def test_exact_resource_memory_and_tmtc_reads_are_digest_pinned() -> None:
    service = ObservationReadService()
    catalog_id, catalog_digest = service_identity(service)

    resource = service.get_resource(
        catalog_id=catalog_id,
        catalog_digest=catalog_digest,
        resource_type="CONFIGURATION",
        resource_id="SIMULATOR.MODE",
    )
    memory = service.memory_lookup(
        catalog_id=catalog_id,
        catalog_digest=catalog_digest,
        memory_region_id="SIMULATOR.TELEMETRY",
        maximum_entries=1,
    )
    telemetry = service.tmtc_lookup(
        catalog_id=catalog_id,
        catalog_digest=catalog_digest,
        direction="TM",
        item_id="TM.POWER.BUS_VOLTAGE",
        maximum_entries=1,
    )

    assert resource["outcome"] == "OK"
    assert memory["outcome"] == "OK"
    assert telemetry["outcome"] == "OK"
    assert telemetry["entries"][0]["direction"] == "TM"


def test_reads_reject_stale_digest_generic_or_ambiguous_queries() -> None:
    service = ObservationReadService()
    catalog_id, catalog_digest = service_identity(service)

    stale = service.get_resource(
        catalog_id=catalog_id,
        catalog_digest="0" * 64,
        resource_type="CONFIGURATION",
        resource_id="SIMULATOR.MODE",
    )
    ambiguous = service.memory_lookup(
        catalog_id=catalog_id,
        catalog_digest=catalog_digest,
        memory_region_id="SIMULATOR.TELEMETRY",
        start_address=0x2000,
        length=1,
        maximum_entries=1,
    )
    generic = service.tmtc_lookup(
        catalog_id=catalog_id,
        catalog_digest=catalog_digest,
        direction="TM",
        qualified_name="SIM.*",
        maximum_entries=128,
    )

    assert stale["outcome"] == "STALE_CATALOG"
    assert ambiguous["outcome"] == "INVALID_ARGUMENT"
    assert generic["outcome"] == "INVALID_ARGUMENT"


def test_catalog_identity_exposes_only_finite_read_only_counts() -> None:
    identity = ObservationReadService().identity()

    assert identity["mutability"] == "READ_ONLY"
    assert identity["resource_count"] == 2
    assert identity["memory_region_count"] == 2
    assert identity["tmtc_item_count"] == 4
    assert identity["limit_set_count"] == 1
