"""Closed authoring profiles, independent of runtime procedure dispatch."""

LEGACY_LANGUAGE_PROFILE = "spell-restricted-ast/0.9"
V19_LANGUAGE_PROFILE = "spell-lrm244-conformance/0.19"
PROJECT_LANGUAGE_PROFILES = frozenset({LEGACY_LANGUAGE_PROFILE, V19_LANGUAGE_PROFILE})
PROFILE_IR_VERSIONS = {
    LEGACY_LANGUAGE_PROFILE: frozenset({"0.3", "0.6", "0.7", "0.8"}),
    V19_LANGUAGE_PROFILE: frozenset({"0.3", "0.6", "0.7", "0.8", "0.11", "0.17", "0.18", "0.19"}),
}


def authoring_ir_allowed(profile: str, ir_version: str, steps: list[dict]) -> bool:
    """Registry/adaptation execution belongs to the fixed reference catalog only."""
    return ir_version in PROFILE_IR_VERSIONS.get(profile, ()) and all(
        not str(step.get("type", "")).startswith(("reference_", "language_"))
        for step in steps
    )
