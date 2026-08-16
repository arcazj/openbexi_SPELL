"""Application boundary for exact, finite v0.7 simulator catalog reads."""

from __future__ import annotations

from typing import Any

from .bundled_observation_catalog import (
    build_bundled_observation_catalog,
    bundled_visibility,
)
from .observation_catalog import Direction, ObservationCatalog


class ObservationReadService:
    def __init__(self, catalog: ObservationCatalog | None = None):
        self.catalog = catalog or build_bundled_observation_catalog()

    def identity(self) -> dict[str, Any]:
        return {
            **self.catalog.identity.as_dict(),
            "mutability": "READ_ONLY",
            "resource_count": len(self.catalog.resources),
            "memory_region_count": len(self.catalog.memory_regions),
            "tmtc_item_count": len(self.catalog.tmtc_items),
            "limit_set_count": len(self.catalog.limit_sets),
        }

    def get_resource(
        self,
        *,
        catalog_id: str,
        catalog_digest: str,
        resource_type: str,
        resource_id: str,
    ) -> dict[str, Any]:
        return self.catalog.get_resource(
            catalog_id=catalog_id,
            catalog_digest=catalog_digest,
            resource_type=resource_type,
            resource_id=resource_id,
            visibility=bundled_visibility(),
        ).as_dict()

    def memory_lookup(
        self,
        *,
        catalog_id: str,
        catalog_digest: str,
        maximum_entries: int,
        memory_region_id: str | None = None,
        start_address: int | None = None,
        length: int | None = None,
    ) -> dict[str, Any]:
        by_region = memory_region_id is not None
        by_address = start_address is not None or length is not None
        if by_region == by_address or (by_address and (start_address is None or length is None)):
            return {
                "operation": "MemoryLookup",
                "outcome": "INVALID_ARGUMENT",
                "catalog_identity": self.catalog.identity.as_dict(),
                "entries": [],
                "reason": "EXACTLY_ONE_LOOKUP_MODE_REQUIRED",
            }
        if by_region:
            result = self.catalog.memory_lookup_region(
                catalog_id=catalog_id,
                catalog_digest=catalog_digest,
                memory_region_id=memory_region_id,
                maximum_entries=maximum_entries,
                visibility=bundled_visibility(),
            )
        else:
            assert start_address is not None and length is not None
            result = self.catalog.memory_lookup_address(
                catalog_id=catalog_id,
                catalog_digest=catalog_digest,
                start_address=start_address,
                length=length,
                maximum_entries=maximum_entries,
                visibility=bundled_visibility(),
            )
        return result.as_dict()

    def tmtc_lookup(
        self,
        *,
        catalog_id: str,
        catalog_digest: str,
        direction: str,
        maximum_entries: int,
        item_id: str | None = None,
        qualified_name: str | None = None,
    ) -> dict[str, Any]:
        try:
            selected_direction: Direction | str = Direction(direction)
        except (TypeError, ValueError):
            selected_direction = direction
        return self.catalog.tmtc_lookup(
            catalog_id=catalog_id,
            catalog_digest=catalog_digest,
            direction=selected_direction,
            maximum_entries=maximum_entries,
            item_id=item_id,
            qualified_name=qualified_name,
            visibility=bundled_visibility(),
        ).as_dict()

    def get_limits(
        self, *, catalog_id: str, catalog_digest: str, item_id: str
    ) -> dict[str, Any]:
        return self.catalog.get_limits(
            catalog_id=catalog_id,
            catalog_digest=catalog_digest,
            item_id=item_id,
            visibility=bundled_visibility(),
        ).as_dict()


__all__ = ["ObservationReadService"]
