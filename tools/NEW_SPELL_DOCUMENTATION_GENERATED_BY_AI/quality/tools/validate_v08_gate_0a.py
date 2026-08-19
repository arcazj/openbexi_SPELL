#!/usr/bin/env python3
"""Validate the accepted SPELL v0.8 Gate 0A and v0.7.0 baseline."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


DOC_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = DOC_ROOT.parent
SCOPE_PATH = (
    DOC_ROOT
    / "requirements"
    / "compatibility"
    / "scopes"
    / "v0.8-gate-0a.json"
)
PROPOSAL_PATH = "SPELL_v0.8_Pre-Implementation.md"
CONTRACT_DIRECTORY = "contracts/v08"

TAG_REF = "refs/tags/v0.7.0"
FORBIDDEN_ALIAS_REF = "refs/tags/v0.7"
TAG_OBJECT_ID = "70e4d46a46d158dee3c63ec37a5d1922b3b61668"
RAW_TAG_OBJECT_SHA256 = (
    "dfa9c0c68cd3c9f3a64768392c001a66b1641e31dcae1ffd5bf2c40197838cae"
)
RAW_TAG_OBJECT_BYTES = 954
PEELED_RELEASE_COMMIT = "cf18e9d887ba0476cbcc3d8194e321332a3ae864"
RELEASE_TREE = "650650627ce5e59e73d92e65d9d4a503e9d348b9"
QUALIFIED_SOURCE_COMMIT = "6ac43c5be7670ead09de821578cc6c6a680af109"
CANDIDATE_COMMIT = "82b497227aff097db9d4c3ff56adf56d76d892ca"
ARTIFACT_TREE = "b6b4a9239e36eaea61da8e7d87cc5bffecfd064f"
SOURCE_FINGERPRINT_SHA256 = (
    "a04e158843acf2da08696e647d16f8f72f6dd329dd807daeb381f85911b817fb"
)
EVIDENCE_FINGERPRINT_SHA256 = (
    "7fe2a643ed335c4057aaac0976de6f1ef944543aae6ca53e9e71b7a5cffcb718"
)
PRODUCT_PACKAGE_SHA256 = (
    "fc9fb26fcb5cea7518f43064beb3ebb40a298c5ec31b93663fd27b0cabcc6633"
)
WORK_PACKAGE_EVIDENCE_SHA256 = (
    "04176843f3769786e8ffb068bb3fd60048aae90b258a365657a7cb0b1d3d6e20"
)
ARCHIVE_PATH = "artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz"
ARCHIVE_SHA256 = "90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2"
SIDECAR_PATH = "artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz.sha256"
SIDECAR_SHA256 = "c35a6d2451e45f9a36fd9a90af47f5f02d5eb58608905e4c77f9cc0b6a95fe7b"
SIDECAR_BYTES = (
    f"{ARCHIVE_SHA256}  openbexi-spell-v0.7.0.tar.gz\n".encode("ascii")
)

TAGGED_BLOBS: dict[str, dict[str, str]] = {
    "SPELL_v0.7_Release.md": {
        "object_id": "d1f1f249e5999d1a4a63b665edeaa70ea7139bb4",
        "sha256": "455a0dc8a572b941b0d7f4546f800500e1f59a91aba2333407dd9348d4dba979",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.7-gate-0b.json"
    ): {
        "object_id": "7522110cfe6e2ac07de09879bb0e47ec5aacd116",
        "sha256": "8b8a6985bf4942d6554f9c10b0d2eaf0cab7cd84adcbea170f00eef87249f28f",
    },
    "artifacts/v0.7/release-qualification.json": {
        "object_id": "821f004641e58a38573d978a4da5bac9acb0e2cf",
        "sha256": "e32e6fd025a8bb22af6a0e93151110f934b29df0a86004eae168e19fde42a70a",
    },
    ARCHIVE_PATH: {
        "object_id": "1dee6392f5c86f01801c71b4093169a7337f514b",
        "sha256": ARCHIVE_SHA256,
    },
    SIDECAR_PATH: {
        "object_id": "28fc25b561460663f2a51726dbfea50bd79423fe",
        "sha256": SIDECAR_SHA256,
    },
}

TRACKED_SOURCE_INPUTS: dict[str, dict[str, str]] = {
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/SOURCE_AUTHORITY.md": {
        "object_id": "02234ec4081c5c0d2b5978b6ce96db889c6c42b6",
        "sha256": "259f762bd37e9fe5e6ce5d581c3036cda88c8c2d3da2c399f4870c43c48026a8",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/preserved/LANGUAGE_REFERENCE_AUTHORITY.md": {
        "object_id": "9933c4b4622cc6997835601444ff3f515a4bf045",
        "sha256": "d98b5855927cd779f361e29b3156930e91dc0b1f489d81333c2901f680d42105",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/COMPATIBILITY_LEDGER.md": {
        "object_id": "9384e9f0d21e7001884ea19dd4966fb62e0bf656",
        "sha256": "7d08e65df3c7a312dfeb3ec9913f522943ded35bc71c6d2c6d5f9c8e9cb86312",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/COMPATIBILITY_SOURCE_INVENTORY.json": {
        "object_id": "657583a72d351ee422358112923df7c38aaaf841",
        "sha256": "5c51f1b06f45003cadfe417e9bffc559b381f1e8a20e2bc9c6f7fc160c09c0b7",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/COMPATIBILITY_LEDGER.json": {
        "object_id": "202612855cbcf59b501044338db203e5250335b2",
        "sha256": "f1d4e20383c81a1109e93b39e2aac04f04b2366e91eae613170488a6acf8458f",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/COMPATIBILITY_RECONCILIATION.json": {
        "object_id": "b3719152779ff6d4e09521d4bb498ffbe4446d8b",
        "sha256": "62c8ad5f678ba313330c35d437d0821c5b097955712860a7e7de697d5327bb85",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/V04_COMPATIBILITY_TECHNICAL_REVIEW.json": {
        "object_id": "9e27acf313503719affb674b1f595055212c554a",
        "sha256": "65a0be691ae96814f3fd295ef28f35cd2e17e19ab7b604b45688f89aecc9ed29",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_compatibility.py": {
        "object_id": "bb42e45f3ba4f2fcf8c9ba67d466cf6192694803",
        "sha256": "deacb9961e9e93f87ef63d27c8791ddc12e387da267b06cd73f9325a0cbe3320",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/architecture/DATA_ARCHITECTURE.md": {
        "object_id": "4534ad40d3321de852072cab65b3b2fbf8118caf",
        "sha256": "48b0e9d53c5e3ae42b7816fa42ac70fbf729b8aa49fbc8dc25995ac9e2e1b2b0",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/SYSTEM_REQUIREMENTS.md": {
        "object_id": "f2112b5f52a9554477662463000554396e43432a",
        "sha256": "0ded4e16d27f9fe780e02ae3bed874853380dd67cf3a06bb3af2250e899723b4",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/procedures/COMPATIBILITY_AND_MIGRATION.md": {
        "object_id": "80b5515f8b4361c02e33cab13e8e3d316ce94857",
        "sha256": "001ed37752c2c9493fdcb8480ee6239044c913c7d7b1a34029867eee644123fd",
    },
}

EXTERNAL_AUTHORITIES: dict[str, dict[str, Any]] = {
    "SPELL-DOCUMENTATION/SPELL - Language Reference - 2.4.4.pdf": {
        "sha256": "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3",
        "size": 2_284_568,
    },
    "SPELL-DOCUMENTATION/SPELL - Driver Development Manual - 2.4.4.pdf": {
        "sha256": "057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5",
        "size": 1_179_207,
    },
}

# Replaced only after all nine contract files pass their independent tests.
CONTRACTS_SHA256 = {
    "manifest.json": "8270ca2f3b43e96c85b33e6a98c79303a0c4b70d75889dbb813c410c70e416e3",
    "typed_values.json": "e546ad93e94f93777bffcd2d8b51335cf934e599400658158b356f23015dc5a9",
    "catalog_uri_dependency.json": "e534039af0e4d4e48004dfadf08813226677b9a851537c123b656fb7fdc99d48",
    "dictionary_exchange.json": "59b1590fefb6784efe28d807f80d2a47617bd855dc872c625ff2d98590129f0a",
    "data_containers.json": "a196cdf9cfd7ff6ae7c2728251e84263a7b2dab5eed0e20debc804e0d39e844b",
    "shared_data.json": "fc6eec064ef0401b9fe159c88da998a6c60ba0e8141b145111749dff641a9737",
    "virtual_files.json": "534edbdc4e4b4c13d04afd306e4d5b51da2cca1ef97c873dd74ad0f80ed4fac8",
    "data_api_authorization.json": "97f9fa70c4d7dc82cf657e3b6caaa4a0fb9489d0c5fe50690086b4ef22666ade",
    "migration_recovery.json": "034efcf98c5d8a60719323515701e4a12ced25873c24bfc4211fd93f6178ba8a",
}

OWNER_REQUEST = (
    "table are not correctly formated for some md file like SPELL_v0.7_Release.md. "
    "fix that. make sure to update all docs as well regarding last version "
    "implemented. then resume and finish up V0.7 asap, asap. once done finish up "
    "V0.8 and v0.9 asap. You have all approvals."
)
PASS_MARKER = (
    "gate=PASS authorized_work_packages=9 proposed_work_packages=9 "
    "claimed_constructs=0 claimed_artifacts=0"
)
OWNER_APPROVAL_MARKER = "V08-GATE-0A OWNER-APPROVAL: APPROVED"

EXPECTED_TAG_MESSAGE = """SPELL v0.7.0

Owner: JC Arcaz
Decision: ACCEPTED
Gate 0B: PASS
Accepted exceptions: None
Operational authorization: None
Compliance determination: None
Cryptographic signature: Not claimed
Release commit: cf18e9d887ba0476cbcc3d8194e321332a3ae864
Qualified source commit: 6ac43c5be7670ead09de821578cc6c6a680af109
Candidate implementation commit: 82b497227aff097db9d4c3ff56adf56d76d892ca
Source fingerprint: a04e158843acf2da08696e647d16f8f72f6dd329dd807daeb381f85911b817fb
Evidence fingerprint: 7fe2a643ed335c4057aaac0976de6f1ef944543aae6ca53e9e71b7a5cffcb718
Product package SHA-256: fc9fb26fcb5cea7518f43064beb3ebb40a298c5ec31b93663fd27b0cabcc6633
Work-package evidence SHA-256: 04176843f3769786e8ffb068bb3fd60048aae90b258a365657a7cb0b1d3d6e20
Final archive SHA-256: 90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2
"""

WORK_PACKAGES = [
    {
        "work_package_id": "V08-DATA-001",
        "title": "Canonical typed value envelope",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": "CANONICAL_TYPED_VALUE_ENVELOPE_BOUNDED_SERIALIZATION_SCHEMA_VERSIONING_CORRUPTION_REJECTION_AND_NO_CODE_EVALUATION",
        "planned_test_ids": [
            "V08-DATA-001-UNIT", "V08-DATA-001-TYPE-MATRIX",
            "V08-DATA-001-SERIALIZATION", "V08-DATA-001-CORRUPTION",
            "V08-DATA-001-SECURITY",
        ],
    },
    {
        "work_package_id": "V08-DATA-002",
        "title": "Versioned local catalogs, URI resolution, and immutable dependencies",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": "VERSIONED_LOCAL_SCDB_GDB_PROC_MMD_USER_CATALOGS_SAFE_URI_RESOLUTION_AND_IMMUTABLE_BOUNDED_DEPENDENCY_GRAPHS_WITH_NO_LIVE_RESOURCE_ACCESS",
        "planned_test_ids": [
            "V08-DATA-002-UNIT", "V08-DATA-002-CONTRACT",
            "V08-DATA-002-GRAPH", "V08-DATA-002-RECOVERY",
            "V08-DATA-002-SECURITY",
        ],
    },
    {
        "work_package_id": "V08-DATA-003",
        "title": "Non-executing DB/IMP dictionary exchange",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": "NON_EXECUTING_PROVENANCE_PRESERVING_DB_IMP_DICTIONARY_IMPORT_EXPORT_WITH_CANONICAL_DIAGNOSTICS_AND_CORRUPTION_RECOVERY",
        "planned_test_ids": [
            "V08-DATA-003-UNIT", "V08-DATA-003-COMPATIBILITY-GOLDEN",
            "V08-DATA-003-IMPORT-EXPORT", "V08-DATA-003-CORRUPTION-RECOVERY",
            "V08-DATA-003-SECURITY",
        ],
    },
    {
        "work_package_id": "V08-DATA-004",
        "title": "Typed DataContainer, Var, ARGS, and IVARS",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": "TYPED_DATACONTAINER_VAR_ARGS_IVARS_SCHEMAS_CONSTRAINTS_DURABLE_PERSISTENCE_AND_RESTART_BEHAVIOR",
        "planned_test_ids": [
            "V08-DATA-004-UNIT", "V08-DATA-004-MATRIX",
            "V08-DATA-004-INTEGRATION", "V08-DATA-004-RECOVERY",
            "V08-DATA-004-SECURITY",
        ],
    },
    {
        "work_package_id": "V08-DATA-005",
        "title": "Durable authorized shared data",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": "AUTHORIZED_SHARED_DATA_NAMESPACES_TYPED_VALUES_ENUMERATION_REVISIONED_COMPARE_AND_SET_CLEAR_OPERATIONS_DURABILITY_AND_AUDIT",
        "planned_test_ids": [
            "V08-DATA-005-UNIT", "V08-DATA-005-INTEGRATION",
            "V08-DATA-005-RACE", "V08-DATA-005-RECOVERY",
            "V08-DATA-005-SECURITY",
        ],
    },
    {
        "work_package_id": "V08-DATA-006",
        "title": "Virtual-root procedure files",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": "VIRTUAL_ROOT_FILE_READ_WRITE_DELETE_AND_DIRECTORY_APIS_WITH_TRAVERSAL_SYMLINK_ENCODING_QUOTA_ATOMICITY_RECOVERY_AND_AUDIT_CONTROLS",
        "planned_test_ids": [
            "V08-DATA-006-UNIT", "V08-DATA-006-INTEGRATION",
            "V08-DATA-006-PATH-SECURITY", "V08-DATA-006-QUOTA-ATOMICITY",
            "V08-DATA-006-RECOVERY",
        ],
    },
    {
        "work_package_id": "V08-DATA-007",
        "title": "Authorized local data API and audit",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": "AUTHENTICATED_DOMAIN_SCOPED_DATA_APIS_WITH_AUTHORIZATION_REVISION_IDEMPOTENCY_TRANSACTIONAL_AUDIT_OUTBOX_AND_NO_DIRECT_DATABASE_ROUTE",
        "planned_test_ids": [
            "V08-DATA-007-CONTRACT", "V08-DATA-007-AUTHORIZATION",
            "V08-DATA-007-IDEMPOTENCY-RACE", "V08-DATA-007-AUDIT-OUTBOX",
            "V08-DATA-007-SECURITY",
        ],
    },
    {
        "work_package_id": "V08-DATA-008",
        "title": "Data migration, backup, and restore",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": "ORDERED_CHECKSUMMED_SQLITE_POSTGRES_DATA_MIGRATIONS_POPULATED_UPGRADE_BACKUP_RESTORE_ROLLBACK_ROLLFORWARD_AND_IDENTITY_PRESERVATION",
        "planned_test_ids": [
            "V08-DATA-008-SCHEMA", "V08-DATA-008-SQLITE",
            "V08-DATA-008-POSTGRES", "V08-DATA-008-BACKUP-RESTORE",
            "V08-DATA-008-MIGRATION-ROLLBACK",
        ],
    },
    {
        "work_package_id": "V08-DATA-009",
        "title": "Cross-feature data-service acceptance",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": "INTEGRATED_TYPED_CATALOG_DICTIONARY_CONTAINER_SHARED_FILE_API_MIGRATION_SEMANTIC_FAULT_RECOVERY_LOAD_AND_SECURITY_ACCEPTANCE",
        "planned_test_ids": [
            "V08-DATA-009-SEMANTIC-GOLDEN", "V08-DATA-009-INTEGRATION",
            "V08-DATA-009-FAULT-RECOVERY", "V08-DATA-009-LOAD",
            "V08-DATA-009-SECURITY",
        ],
    },
]

REVIEWED_ARTIFACT_IDS_BY_WORK_PACKAGE = {
    "V08-DATA-001": [
        "CMP-LRM244-TYPE-BOOLEAN", "CMP-LRM244-TYPE-DICTIONARY",
        "CMP-LRM244-TYPE-FLOAT", "CMP-LRM244-TYPE-INTEGER",
        "CMP-LRM244-TYPE-LIST", "CMP-LRM244-TYPE-STRING",
    ],
    "V08-DATA-002": [
        "CMP-LRM244-CONSTANT-PROC-KEY-ARGS",
        "CMP-LRM244-CONSTANT-PROC-KEY-INPUT-DATA",
        "CMP-LRM244-CONSTANT-PROC-KEY-NAME",
        "CMP-LRM244-CONSTANT-PROC-KEY-OUTPUT-DATA",
        "CMP-LRM244-CONSTANT-PROC-KEY-PARENT",
        "CMP-LRM244-CONSTANT-PROC-KEY-PREV-STEP",
        "CMP-LRM244-CONSTANT-PROC-KEY-STEP", "CMP-LRM244-DATABASE-GDB",
        "CMP-LRM244-DATABASE-PROC", "CMP-LRM244-DATABASE-SCDB",
        "CMP-LRM244-EXAMPLE-135", "CMP-LRM244-EXAMPLE-136",
        "CMP-LRM244-EXAMPLE-137", "CMP-LRM244-EXAMPLE-139",
        "CMP-LRM244-EXAMPLE-140", "CMP-LRM244-EXAMPLE-141",
        "CMP-LRM244-EXAMPLE-142", "CMP-LRM244-SECTION-4-15-095",
        "CMP-LRM244-SECTION-4-15-1-096", "CMP-LRM244-SECTION-4-15-2-097",
        "CMP-LRM244-SECTION-4-15-3-098", "CMP-LRM244-SECTION-4-15-4-099",
        "CMP-LRM244-SYNTAX-URI-MMD", "CMP-LRM244-SYNTAX-URI-USR",
    ],
    "V08-DATA-003": [
        "CMP-LRM244-EXAMPLE-138", "CMP-LRM244-EXAMPLE-143",
        "CMP-LRM244-EXAMPLE-144", "CMP-LRM244-EXAMPLE-145",
        "CMP-LRM244-EXAMPLE-146", "CMP-LRM244-EXAMPLE-147",
        "CMP-LRM244-EXAMPLE-148", "CMP-LRM244-FUNCTION-CREATEDICTIONARY",
        "CMP-LRM244-FUNCTION-LOADDICTIONARY",
        "CMP-LRM244-FUNCTION-SAVEDICTIONARY",
        "CMP-LRM244-METHOD-DICTIONARY-HAS-KEY",
        "CMP-LRM244-SECTION-4-15-5-100",
        "CMP-LRM244-SECTION-4-15-5-1-101",
        "CMP-LRM244-SECTION-4-15-5-2-102",
        "CMP-LRM244-SECTION-4-15-5-3-103",
        "CMP-LRM244-SECTION-4-15-5-4-104",
        "CMP-LRM244-SECTION-4-15-6-105",
        "CMP-LRM244-TYPE-DATABASEDICTIONARY",
    ],
    "V08-DATA-004": [
        "CMP-LRM244-DATA-CONTAINER-ARGS", "CMP-LRM244-DATA-CONTAINER-IVARS",
        "CMP-LRM244-EXAMPLE-149", "CMP-LRM244-EXAMPLE-150",
        "CMP-LRM244-SECTION-1-2-106", "CMP-LRM244-SYNTAX-DATA-CONTAINER-VAR",
        "CMP-LRM244-TYPE-DATACONTAINER",
        "CMP-LRM244-TYPE-DATA-CONTAINER-BOOLEAN",
        "CMP-LRM244-TYPE-DATA-CONTAINER-DATETIME",
        "CMP-LRM244-TYPE-DATA-CONTAINER-FLOAT",
        "CMP-LRM244-TYPE-DATA-CONTAINER-LONG",
        "CMP-LRM244-TYPE-DATA-CONTAINER-RELTIME",
        "CMP-LRM244-TYPE-DATA-CONTAINER-STRING", "CMP-LRM244-TYPE-VAR",
    ],
    "V08-DATA-005": [
        "CMP-LRM244-CONSTANT-SCOPE-GLOBAL", "CMP-LRM244-EXAMPLE-177",
        "CMP-LRM244-EXAMPLE-178", "CMP-LRM244-EXAMPLE-179",
        "CMP-LRM244-EXAMPLE-180", "CMP-LRM244-EXAMPLE-181",
        "CMP-LRM244-EXAMPLE-182", "CMP-LRM244-EXAMPLE-183",
        "CMP-LRM244-EXAMPLE-184", "CMP-LRM244-EXAMPLE-185",
        "CMP-LRM244-EXAMPLE-186", "CMP-LRM244-EXAMPLE-187",
        "CMP-LRM244-EXAMPLE-188", "CMP-LRM244-EXAMPLE-189",
        "CMP-LRM244-EXAMPLE-190", "CMP-LRM244-FUNCTION-ADDSHAREDDATASCOPE",
        "CMP-LRM244-FUNCTION-CANDIDATE-CLEARSHAREDDATASCOPE",
        "CMP-LRM244-FUNCTION-CLEARSHAREDDATA",
        "CMP-LRM244-FUNCTION-CLEARSHAREDDATASCOPES",
        "CMP-LRM244-FUNCTION-GETSHAREDDATA",
        "CMP-LRM244-FUNCTION-GETSHAREDDATAKEYS",
        "CMP-LRM244-FUNCTION-GETSHAREDDATASCOPES",
        "CMP-LRM244-FUNCTION-SETSHAREDDATA", "CMP-LRM244-MODIFIER-EXPECTED",
        "CMP-LRM244-MODIFIER-SCOPE", "CMP-LRM244-SECTION-4-19-1-130",
        "CMP-LRM244-SECTION-4-19-129", "CMP-LRM244-SECTION-4-19-2-131",
        "CMP-LRM244-SECTION-4-19-3-132", "CMP-LRM244-SECTION-4-19-4-133",
        "CMP-LRM244-SECTION-4-19-5-134",
        "CMP-LRM244-SYNTAX-SHARED-TEST-AND-SET",
        "CMP-LRM244-TYPE-PRIMITIVESHAREDVALUE",
    ],
    "V08-DATA-006": [
        "CMP-LRM244-CONSTANT-FILE-MODE-APPEND",
        "CMP-LRM244-CONSTANT-FILE-MODE-READ",
        "CMP-LRM244-CONSTANT-FILE-MODE-READ-WRITE",
        "CMP-LRM244-CONSTANT-FILE-MODE-WRITE", "CMP-LRM244-EXAMPLE-162",
        "CMP-LRM244-EXAMPLE-163", "CMP-LRM244-EXAMPLE-164",
        "CMP-LRM244-EXAMPLE-165", "CMP-LRM244-EXAMPLE-166",
        "CMP-LRM244-EXAMPLE-167", "CMP-LRM244-EXAMPLE-168",
        "CMP-LRM244-FUNCTION-CANDIDATE-FILE", "CMP-LRM244-FUNCTION-CLOSEFILE",
        "CMP-LRM244-FUNCTION-DELETEFILE", "CMP-LRM244-FUNCTION-OPENFILE",
        "CMP-LRM244-FUNCTION-READDIRECTORY", "CMP-LRM244-FUNCTION-READFILE",
        "CMP-LRM244-FUNCTION-WRITEFILE", "CMP-LRM244-METHOD-FILE-BASENAME",
        "CMP-LRM244-METHOD-FILE-CANREAD", "CMP-LRM244-METHOD-FILE-CANWRITE",
        "CMP-LRM244-METHOD-FILE-DIRNAME", "CMP-LRM244-METHOD-FILE-EXISTS",
        "CMP-LRM244-METHOD-FILE-FILENAME", "CMP-LRM244-METHOD-FILE-ISDIR",
        "CMP-LRM244-METHOD-FILE-ISFILE", "CMP-LRM244-METHOD-FILE-ISOPEN",
        "CMP-LRM244-MODIFIER-MODE", "CMP-LRM244-OPERATOR-FILE-PATH-APPEND",
        "CMP-LRM244-SECTION-4-17-1-116", "CMP-LRM244-SECTION-4-17-115",
        "CMP-LRM244-SECTION-4-17-2-117", "CMP-LRM244-SECTION-4-17-3-118",
        "CMP-LRM244-SECTION-4-17-4-119", "CMP-LRM244-SECTION-4-17-5-120",
        "CMP-LRM244-SECTION-4-17-6-121", "CMP-LRM244-SECTION-4-17-7-122",
        "CMP-LRM244-SECTION-4-17-8-123", "CMP-LRM244-TYPE-FILE",
        "CMP-LRM244-TYPE-FILEHANDLE",
    ],
}
NEGATIVE_ONLY_ARTIFACT_IDS = [
    "CMP-LRM244-FUNCTION-CANDIDATE-CLEARSHAREDDATASCOPE"
]
IMPLEMENTATION_AUTHORIZED_ARTIFACT_IDS_BY_WORK_PACKAGE = {
    package_id: [
        artifact_id
        for artifact_id in artifact_ids
        if artifact_id not in NEGATIVE_ONLY_ARTIFACT_IDS
    ]
    for package_id, artifact_ids in REVIEWED_ARTIFACT_IDS_BY_WORK_PACKAGE.items()
}
REVIEWED_ARTIFACT_ID_COUNT = 135
REVIEWED_ARTIFACT_IDS_SHA256 = (
    "2f59a5b185720d5707dd81ebfa6a9554eaec3dc067fba742f90342a94ff9f8e4"
)
NEGATIVE_ONLY_ARTIFACT_IDS_SHA256 = (
    "1ed876c1938566ec21d0b8ce69e26362c560fe97a25b755ec02337706c34ff07"
)
IMPLEMENTATION_AUTHORIZED_ARTIFACT_ID_COUNT = 134
IMPLEMENTATION_AUTHORIZED_ARTIFACT_IDS_SHA256 = (
    "ec133a9f2c1eb44586be52f663e67cb178e913c0a788b6e1283f7cc3b24bbbe6"
)

EXPECTED_SCOPE: dict[str, Any] = {
    "schema_version": "ng-spell-v08-gate-0a-scope/1",
    "gate_id": "V08-GATE-0A",
    "status": "PASS",
    "target_increment": "v0.8",
    "target_release": "v0.8.0",
    "scope_profile": "LOCAL_SYNTHETIC_NON_CUI_DATA_SERVICE",
    "decision": {
        "owner": "JC Arcaz",
        "proposal_date": "2026-08-17",
        "approval_date": "2026-08-17",
        "authorization": "V08_DATA_001_THROUGH_V08_DATA_009",
        "owner_request": OWNER_REQUEST,
        "precondition": "ANNOTATED_V0_7_0_ACCEPTED_RELEASE_TAG_VERIFIED",
        "owner_approval_recorded": True,
    },
    "approval_mechanics": {
        "pass_validator_marker": PASS_MARKER,
        "required_owner_approval_marker": OWNER_APPROVAL_MARKER,
        "required_marker_location": "STANDALONE_LINE_IN_SPELL_V0_8_PRE_IMPLEMENTATION_MD",
        "marker_present": True,
        "required_scope_status_after_approval": "PASS",
        "required_authorization_after_approval": "EXPLICIT_BOUNDED_WORK_PACKAGE_ID_LIST",
        "authorized_work_package_ids": [
            f"V08-DATA-{index:03d}" for index in range(1, 10)
        ],
        "automatic_approval_from_request_or_tool_success": False,
    },
    "accepted_baseline": {
        "tag_ref": TAG_REF,
        "tag_object_type": "tag",
        "tag_object_id": TAG_OBJECT_ID,
        "raw_tag_object_sha256": RAW_TAG_OBJECT_SHA256,
        "raw_tag_object_bytes": RAW_TAG_OBJECT_BYTES,
        "peeled_release_commit": PEELED_RELEASE_COMMIT,
        "release_tree": RELEASE_TREE,
        "qualified_source_commit": QUALIFIED_SOURCE_COMMIT,
        "candidate_commit": CANDIDATE_COMMIT,
        "artifact_tree": ARTIFACT_TREE,
        "source_fingerprint_sha256": SOURCE_FINGERPRINT_SHA256,
        "evidence_fingerprint_sha256": EVIDENCE_FINGERPRINT_SHA256,
        "product_package_sha256": PRODUCT_PACKAGE_SHA256,
        "work_package_evidence_sha256": WORK_PACKAGE_EVIDENCE_SHA256,
        "tagged_blobs": TAGGED_BLOBS,
        "accepted_artifact_pair": {
            "archive_path": ARCHIVE_PATH,
            "archive_sha256": ARCHIVE_SHA256,
            "sidecar_path": SIDECAR_PATH,
            "sidecar_sha256": SIDECAR_SHA256,
            "sidecar_bytes": len(SIDECAR_BYTES),
            "sidecar_ascii": SIDECAR_BYTES.decode("ascii").rstrip("\n"),
        },
    },
    "source_authorities": {
        "external_files": EXTERNAL_AUTHORITIES,
        "tracked_inputs": TRACKED_SOURCE_INPUTS,
    },
    "authorization_contracts": {
        "directory": CONTRACT_DIRECTORY,
        "matrix_count": 8,
        "file_count": 9,
        "files_sha256": CONTRACTS_SHA256,
    },
    "compatibility_authorization": {
        "source": "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/COMPATIBILITY_LEDGER.json",
        "hash_serialization": "globally sorted unique ASCII artifact IDs joined by LF with one final LF",
        "reviewed_artifact_ids_by_work_package": REVIEWED_ARTIFACT_IDS_BY_WORK_PACKAGE,
        "reviewed_artifact_id_count": REVIEWED_ARTIFACT_ID_COUNT,
        "reviewed_artifact_ids_sha256": REVIEWED_ARTIFACT_IDS_SHA256,
        "negative_only_artifact_ids": NEGATIVE_ONLY_ARTIFACT_IDS,
        "negative_only_artifact_ids_sha256": NEGATIVE_ONLY_ARTIFACT_IDS_SHA256,
        "implementation_authorized_artifact_ids_by_work_package": IMPLEMENTATION_AUTHORIZED_ARTIFACT_IDS_BY_WORK_PACKAGE,
        "implementation_authorized_artifact_id_count": IMPLEMENTATION_AUTHORIZED_ARTIFACT_ID_COUNT,
        "implementation_authorized_artifact_ids_sha256": IMPLEMENTATION_AUTHORIZED_ARTIFACT_IDS_SHA256,
        "accepted_persisted_ir_versions": ["0.3", "0.6", "0.7"],
        "planned_internal_ir_version": "0.8",
        "claimed_construct_ids": [],
        "claimed_artifact_ids": [],
        "compatibility_ledger_rows_added": 0,
        "v0_7_scope_rows_changed": 0,
        "unlisted_artifact_authorized": False,
    },
    "proposed_work_packages": WORK_PACKAGES,
    "claims": {
        "v0_7_release_accepted": True,
        "v0_8_program_proposed": True,
        "v0_8_implementation_authorized": True,
        "v0_8_implementation_claimed_by_gate": False,
        "v0_8_release_accepted": False,
        "data_constructs_implemented": False,
        "product_artifacts_implemented": False,
        "operational_authorization": False,
        "deployment_approval": False,
        "compliance_determination": False,
        "cryptographic_signature_verified": False,
    },
    "explicit_exclusions": [
        "SCOPE_BEYOND_V08_DATA_001_THROUGH_V08_DATA_009",
        "NON_LOCAL_NON_SYNTHETIC_CUI_CLASSIFIED_PRODUCTION_OR_OPERATIONAL_DATA",
        "LIVE_GCS_SPACECRAFT_MISSION_NETWORK_TELEMETRY_TELECOMMAND_DRIVER_MUTATION_OR_EXTERNAL_EFFECT_ROUTE",
        "ARBITRARY_SOURCE_PYTHON_EXPRESSION_TEMPLATE_FUNCTION_SHELL_NATIVE_BYTECODE_PICKLE_EXECUTABLE_IMPORT_OR_GENERIC_FILTER_EVALUATION",
        "DIRECT_BROWSER_OR_WORKER_DATABASE_OBJECT_ADMIN_HOST_FILESYSTEM_SECRET_CREDENTIAL_OR_UNRESTRICTED_NETWORK_ACCESS",
        "ABSOLUTE_TRAVERSAL_SYMLINK_REPARSE_DEVICE_ALTERNATE_DATA_STREAM_URL_OR_UNBOUNDED_FILE_ACCESS",
        "UNBOUNDED_VALUE_SCHEMA_CATALOG_DEPENDENCY_NAMESPACE_ENUMERATION_QUERY_TRANSACTION_RETRY_QUOTA_OR_RETENTION",
        "SILENT_COERCION_AMBIGUOUS_FORMAT_BEST_EFFORT_CORRUPTION_RECOVERY_LAST_WRITER_WINS_OR_PARTIAL_WRITE_SUCCESS",
        "AMBIGUOUS_SINGULAR_CLEAR_SHARED_DATA_SCOPE_ALIAS_IMPLEMENTATION",
        "UNREVIEWED_LANGUAGE_IR_API_SCHEMA_DEPENDENCY_MIGRATION_OR_COMPATIBILITY_CHANGE",
        "IMPLEMENTATION_OUTSIDE_EXACT_AUTHORIZED_WORK_PACKAGE_CONTRACT_AND_ARTIFACT_BOUNDARIES",
        "IMPLEMENTATION_RELEASE_DEPLOYMENT_OPERATIONAL_COMPLIANCE_OR_SIGNATURE_CLAIM",
    ],
}

POST_BASELINE_ONLY_PATHS = (
    PROPOSAL_PATH,
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.8-gate-0a.json",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v08_gate_0a.py",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v08_gate_0a.py",
    "backend/tests/test_v08_contract_matrices.py",
    *(f"{CONTRACT_DIRECTORY}/{name}" for name in CONTRACTS_SHA256),
)


class DuplicateJSONKeyError(ValueError):
    """Raised when a JSON object contains a duplicate key."""


class GitValidationError(RuntimeError):
    """Raised when a required Git query cannot be completed exactly."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> Any:
    raise ValueError(f"non-finite JSON value: {value}")


def parse_strict_json(raw: bytes, label: str, maximum_bytes: int) -> Any:
    if len(raw) > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} bytes")
    text = raw.decode("utf-8")
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
    )


def read_json(path: Path = SCOPE_PATH) -> Any:
    return parse_strict_json(path.read_bytes(), "Gate 0A scope", 1024 * 1024)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _selection_digest(artifact_ids: Iterable[str]) -> str:
    values = sorted(artifact_ids)
    if len(values) != len(set(values)):
        raise ValueError("artifact selection contains duplicate IDs")
    return sha256_bytes(("\n".join(values) + "\n").encode("ascii"))


def _flatten_groups(groups: dict[str, list[str]]) -> list[str]:
    return [artifact_id for values in groups.values() for artifact_id in values]


def _format_keys(keys: Iterable[Any]) -> str:
    return ", ".join(sorted(repr(key) for key in keys))


def exact_value_errors(actual: Any, expected: Any, path: str = "scope") -> list[str]:
    if type(actual) is not type(expected):
        return [
            f"{path} type differs: expected {type(expected).__name__}, "
            f"got {type(actual).__name__}"
        ]
    if isinstance(expected, dict):
        errors: list[str] = []
        missing = expected.keys() - actual.keys()
        extra = actual.keys() - expected.keys()
        if missing:
            errors.append(f"{path} missing keys: {_format_keys(missing)}")
        if extra:
            errors.append(f"{path} has unauthorized keys: {_format_keys(extra)}")
        for key in sorted(expected.keys() & actual.keys()):
            errors.extend(exact_value_errors(actual[key], expected[key], f"{path}.{key}"))
        return errors
    if isinstance(expected, list):
        errors = []
        if len(actual) != len(expected):
            errors.append(
                f"{path} length differs: expected {len(expected)}, got {len(actual)}"
            )
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            errors.extend(exact_value_errors(actual_item, expected_item, f"{path}[{index}]"))
        return errors
    if actual != expected:
        return [f"{path} value differs"]
    return []


def _scope_summary(payload: Any, valid: bool) -> dict[str, Any]:
    proposed = authorized = claimed_constructs = claimed_artifacts = 0
    if isinstance(payload, dict):
        packages = payload.get("proposed_work_packages")
        if isinstance(packages, list):
            proposed = len(packages)
        mechanics = payload.get("approval_mechanics")
        if isinstance(mechanics, dict):
            ids = mechanics.get("authorized_work_package_ids")
            if isinstance(ids, list):
                authorized = len(ids)
        compatibility = payload.get("compatibility_authorization")
        if isinstance(compatibility, dict):
            constructs = compatibility.get("claimed_construct_ids")
            artifacts = compatibility.get("claimed_artifact_ids")
            if isinstance(constructs, list):
                claimed_constructs = len(constructs)
            if isinstance(artifacts, list):
                claimed_artifacts = len(artifacts)
    return {
        "gate": "PASS" if valid else "FAIL",
        "authorized_work_packages": authorized,
        "proposed_work_packages": proposed,
        "claimed_constructs": claimed_constructs,
        "claimed_artifacts": claimed_artifacts,
    }


def validate_scope_payload(payload: Any) -> tuple[list[str], dict[str, Any]]:
    errors = exact_value_errors(payload, EXPECTED_SCOPE)
    return errors, _scope_summary(payload, not errors)


def validate_scope(payload: Any) -> list[str]:
    return validate_scope_payload(payload)[0]


def validate_tag_payload(raw_tag: bytes) -> list[str]:
    errors: list[str] = []
    if len(raw_tag) != RAW_TAG_OBJECT_BYTES:
        errors.append("v0.7.0 raw tag object byte count differs")
    if sha256_bytes(raw_tag) != RAW_TAG_OBJECT_SHA256:
        errors.append("v0.7.0 raw tag object SHA-256 differs")
    git_object = b"tag " + str(len(raw_tag)).encode("ascii") + b"\0" + raw_tag
    if hashlib.sha1(git_object).hexdigest() != TAG_OBJECT_ID:
        errors.append("v0.7.0 tag object ID does not match its raw bytes")
    headers, separator, message = raw_tag.partition(b"\n\n")
    if not separator:
        errors.append("v0.7.0 tag object lacks a message boundary")
        return errors
    header_lines = headers.splitlines()
    expected_prefix = [
        f"object {PEELED_RELEASE_COMMIT}".encode("ascii"),
        b"type commit",
        b"tag v0.7.0",
    ]
    if header_lines[:3] != expected_prefix or len(header_lines) != 4:
        errors.append("v0.7.0 tag object headers differ")
    if len(header_lines) == 4 and not header_lines[3].startswith(b"tagger "):
        errors.append("v0.7.0 tagger header differs")
    try:
        decoded = message.decode("utf-8")
    except UnicodeDecodeError:
        errors.append("v0.7.0 tag message is not strict UTF-8")
        return errors
    if decoded != EXPECTED_TAG_MESSAGE:
        errors.append("v0.7.0 tag message differs from the accepted release record")
    return errors


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_REPLACE_REF_BASE",
    ):
        environment.pop(name, None)
    environment.update(
        {"GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C", "LANG": "C"}
    )
    return environment


def run_git(
    arguments: list[str],
    workspace_root: Path = WORKSPACE_ROOT,
    accepted_returncodes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=workspace_root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitValidationError(f"cannot run git {' '.join(arguments)}: {exc}") from exc
    if result.returncode not in accepted_returncodes:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise GitValidationError(
            f"git {' '.join(arguments)} failed ({result.returncode}): {detail}"
        )
    return result


def _single_ascii_line(payload: bytes, label: str) -> str:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GitValidationError(f"{label} is not ASCII") from exc
    if len(lines) != 1 or not lines[0]:
        raise GitValidationError(f"{label} did not return exactly one line")
    return lines[0]


def _validate_tagged_blob(
    relative_path: str,
    expected: dict[str, str],
    workspace_root: Path = WORKSPACE_ROOT,
) -> tuple[list[str], bytes | None]:
    errors: list[str] = []
    expected_id = expected["object_id"]
    expected_record = f"100644 blob {expected_id}\t{relative_path}\0".encode("utf-8")
    listing = run_git(
        ["ls-tree", "-z", PEELED_RELEASE_COMMIT, "--", relative_path], workspace_root
    ).stdout
    if listing != expected_record:
        errors.append(f"tagged baseline tree entry differs: {relative_path}")
    resolved = _single_ascii_line(
        run_git(
            ["rev-parse", "--verify", f"{PEELED_RELEASE_COMMIT}:{relative_path}"],
            workspace_root,
        ).stdout,
        f"tagged blob ID for {relative_path}",
    )
    if resolved != expected_id:
        errors.append(f"tagged baseline blob ID differs: {relative_path}")
    object_type = _single_ascii_line(
        run_git(["cat-file", "-t", expected_id], workspace_root).stdout,
        f"tagged object type for {relative_path}",
    )
    if object_type != "blob":
        errors.append(f"tagged baseline object is not a blob: {relative_path}")
        return errors, None
    payload = run_git(["cat-file", "blob", expected_id], workspace_root).stdout
    if sha256_bytes(payload) != expected["sha256"]:
        errors.append(f"tagged baseline blob SHA-256 differs: {relative_path}")
    return errors, payload


def validate_archive_sidecar(archive: bytes, sidecar: bytes, label: str) -> list[str]:
    errors: list[str] = []
    if sha256_bytes(archive) != ARCHIVE_SHA256:
        errors.append(f"{label} archive SHA-256 differs")
    if sha256_bytes(sidecar) != SIDECAR_SHA256:
        errors.append(f"{label} sidecar SHA-256 differs")
    if sidecar != SIDECAR_BYTES:
        errors.append(f"{label} sidecar bytes differ")
    return errors


def _read_regular_file(path: Path, maximum_bytes: int, label: str) -> bytes:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} is not a non-symlink regular file")
    if metadata.st_size > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} bytes")
    return path.read_bytes()


def validate_contract_directory(directory: Path | None = None) -> list[str]:
    root = directory or (WORKSPACE_ROOT / CONTRACT_DIRECTORY)
    errors: list[str] = []
    try:
        metadata = root.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            return ["v0.8 contract directory is not a non-symlink directory"]
        names = sorted(item.name for item in root.iterdir())
    except OSError as exc:
        return [f"cannot inspect v0.8 contract directory: {exc}"]
    expected_names = sorted(CONTRACTS_SHA256)
    if names != expected_names:
        errors.append(
            "v0.8 contract directory inventory differs: "
            f"expected {expected_names!r}, got {names!r}"
        )
    for name, expected_sha256 in CONTRACTS_SHA256.items():
        path = root / name
        try:
            raw = _read_regular_file(path, 1024 * 1024, f"v0.8 contract {name}")
            payload = parse_strict_json(raw, f"v0.8 contract {name}", 1024 * 1024)
            if not isinstance(payload, dict):
                errors.append(f"v0.8 contract is not a JSON object: {name}")
            if sha256_bytes(raw) != expected_sha256:
                errors.append(f"v0.8 contract SHA-256 differs: {name}")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"cannot validate v0.8 contract {name}: {exc}")
    return errors


def validate_compatibility_selection(workspace_root: Path = WORKSPACE_ROOT) -> list[str]:
    errors: list[str] = []
    reviewed = _flatten_groups(REVIEWED_ARTIFACT_IDS_BY_WORK_PACKAGE)
    authorized = _flatten_groups(IMPLEMENTATION_AUTHORIZED_ARTIFACT_IDS_BY_WORK_PACKAGE)
    try:
        if len(reviewed) != REVIEWED_ARTIFACT_ID_COUNT or len(set(reviewed)) != len(reviewed):
            errors.append("reviewed compatibility artifact cardinality differs")
        if _selection_digest(reviewed) != REVIEWED_ARTIFACT_IDS_SHA256:
            errors.append("reviewed compatibility artifact digest differs")
        if _selection_digest(NEGATIVE_ONLY_ARTIFACT_IDS) != NEGATIVE_ONLY_ARTIFACT_IDS_SHA256:
            errors.append("negative-only compatibility artifact digest differs")
        if len(authorized) != IMPLEMENTATION_AUTHORIZED_ARTIFACT_ID_COUNT or len(set(authorized)) != len(authorized):
            errors.append("implementation-authorized artifact cardinality differs")
        if _selection_digest(authorized) != IMPLEMENTATION_AUTHORIZED_ARTIFACT_IDS_SHA256:
            errors.append("implementation-authorized artifact digest differs")
        if set(authorized) != set(reviewed) - set(NEGATIVE_ONLY_ARTIFACT_IDS):
            errors.append("implementation allowlist is not reviewed set minus negative-only set")
        if set(NEGATIVE_ONLY_ARTIFACT_IDS) & set(authorized):
            errors.append("negative-only artifact entered implementation allowlist")
    except (UnicodeEncodeError, ValueError) as exc:
        errors.append(f"cannot validate compatibility selection digest: {exc}")

    ledger_path = (
        workspace_root
        / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI"
        / "requirements"
        / "compatibility"
        / "COMPATIBILITY_LEDGER.json"
    )
    try:
        ledger = parse_strict_json(
            _read_regular_file(ledger_path, 8 * 1024 * 1024, "compatibility ledger"),
            "compatibility ledger",
            8 * 1024 * 1024,
        )
        rows = ledger.get("rows") if isinstance(ledger, dict) else None
        if not isinstance(rows, list):
            return errors + ["compatibility ledger rows are not a list"]
        row_map: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("ArtifactId"), str):
                continue
            artifact_id = row["ArtifactId"]
            if artifact_id in row_map:
                errors.append(f"compatibility ledger duplicates {artifact_id}")
            row_map[artifact_id] = row
        for artifact_id in reviewed:
            row = row_map.get(artifact_id)
            if row is None:
                errors.append(f"reviewed compatibility artifact is absent: {artifact_id}")
                continue
            if row.get("SourceHash") != EXTERNAL_AUTHORITIES[
                "SPELL-DOCUMENTATION/SPELL - Language Reference - 2.4.4.pdf"
            ]["sha256"]:
                errors.append(f"reviewed compatibility source differs: {artifact_id}")
            if row.get("Status") != "DispositionApproved":
                errors.append(f"reviewed compatibility status differs: {artifact_id}")
            if row.get("TargetIncrement") != "Deferred" or row.get("Disposition") != "EXCLUDE":
                errors.append(f"historical compatibility disposition differs: {artifact_id}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"cannot validate compatibility ledger selection: {exc}")
    return errors


def _validate_release_manifest(raw: bytes) -> list[str]:
    errors: list[str] = []
    try:
        payload = parse_strict_json(raw, "tagged v0.7 release qualification", 2 * 1024 * 1024)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return [f"cannot parse tagged v0.7 release qualification: {exc}"]
    expected = {
        "schema_version": "spell.v07.release-qualification/1",
        "product_version": "0.7.0",
        "scope_profile": "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
        "overall_pass": True,
    }
    for key, value in expected.items():
        if not isinstance(payload, dict) or payload.get(key) != value:
            errors.append(f"tagged v0.7 release qualification {key} differs")
    if isinstance(payload, dict):
        decision = payload.get("decision")
        if not isinstance(decision, dict) or decision.get("accepted_exceptions") != []:
            errors.append("tagged v0.7 accepted exceptions differ")
        source = payload.get("qualified_source")
        expected_source = {
            "commit": QUALIFIED_SOURCE_COMMIT,
            "candidate_commit": CANDIDATE_COMMIT,
            "source_fingerprint_sha256": SOURCE_FINGERPRINT_SHA256,
            "product_package_sha256": PRODUCT_PACKAGE_SHA256,
        }
        if not isinstance(source, dict):
            errors.append("tagged v0.7 qualified source is missing")
        else:
            for key, value in expected_source.items():
                if source.get(key) != value:
                    errors.append(f"tagged v0.7 qualified source {key} differs")
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict) or evidence.get("evidence_fingerprint_sha256") != EVIDENCE_FINGERPRINT_SHA256:
            errors.append("tagged v0.7 evidence fingerprint differs")
        work = payload.get("work_package")
        if not isinstance(work, dict) or work.get("evidence_sha256") != WORK_PACKAGE_EVIDENCE_SHA256:
            errors.append("tagged v0.7 work-package evidence differs")
    return errors


def validate_git_baseline(workspace_root: Path = WORKSPACE_ROOT) -> list[str]:
    errors: list[str] = []
    try:
        initial_ref = _single_ascii_line(
            run_git(["show-ref", "--verify", "--hash", TAG_REF], workspace_root).stdout,
            TAG_REF,
        )
        if initial_ref != TAG_OBJECT_ID:
            errors.append("refs/tags/v0.7.0 does not name the accepted tag object")
        alias = run_git(
            ["show-ref", "--verify", "--quiet", FORBIDDEN_ALIAS_REF],
            workspace_root,
            accepted_returncodes=(0, 1),
        )
        if alias.returncode == 0:
            errors.append("forbidden v0.7 alias tag exists")
        object_type = _single_ascii_line(
            run_git(["cat-file", "-t", TAG_OBJECT_ID], workspace_root).stdout,
            "v0.7.0 tag object type",
        )
        if object_type != "tag":
            errors.append("v0.7.0 is not an annotated tag object")
        raw_tag = run_git(["cat-file", "tag", TAG_OBJECT_ID], workspace_root).stdout
        errors.extend(validate_tag_payload(raw_tag))
        peeled = _single_ascii_line(
            run_git(["rev-parse", "--verify", f"{TAG_REF}^{{commit}}"], workspace_root).stdout,
            "v0.7.0 peeled release commit",
        )
        if peeled != PEELED_RELEASE_COMMIT:
            errors.append("v0.7.0 peeled release commit differs")
        release_tree = _single_ascii_line(
            run_git(["rev-parse", f"{PEELED_RELEASE_COMMIT}^{{tree}}"], workspace_root).stdout,
            "v0.7.0 release tree",
        )
        if release_tree != RELEASE_TREE:
            errors.append("v0.7.0 release tree differs")
        release_line = _single_ascii_line(
            run_git(["rev-list", "--parents", "-n", "1", PEELED_RELEASE_COMMIT], workspace_root).stdout,
            "v0.7.0 release ancestry",
        ).split()
        if release_line != [PEELED_RELEASE_COMMIT, QUALIFIED_SOURCE_COMMIT]:
            errors.append("v0.7.0 release commit does not have the exact qualified parent")
        qualified_line = _single_ascii_line(
            run_git(["rev-list", "--parents", "-n", "1", QUALIFIED_SOURCE_COMMIT], workspace_root).stdout,
            "v0.7 qualified-source ancestry",
        ).split()
        if qualified_line != [QUALIFIED_SOURCE_COMMIT, CANDIDATE_COMMIT]:
            errors.append("v0.7 qualified source does not have the exact candidate parent")
        artifact_tree = _single_ascii_line(
            run_git(
                ["rev-parse", "--verify", f"{PEELED_RELEASE_COMMIT}:artifacts/v0.7"],
                workspace_root,
            ).stdout,
            "accepted artifacts/v0.7 tree",
        )
        if artifact_tree != ARTIFACT_TREE:
            errors.append("accepted artifacts/v0.7 tree differs")
        if _single_ascii_line(
            run_git(["cat-file", "-t", ARTIFACT_TREE], workspace_root).stdout,
            "accepted artifacts/v0.7 object type",
        ) != "tree":
            errors.append("accepted artifacts/v0.7 object is not a tree")
        ancestor = run_git(
            ["merge-base", "--is-ancestor", PEELED_RELEASE_COMMIT, "HEAD"],
            workspace_root,
            accepted_returncodes=(0, 1),
        )
        if ancestor.returncode != 0:
            errors.append("accepted v0.7.0 release commit is not an ancestor of HEAD")

        tagged_payloads: dict[str, bytes] = {}
        for relative_path, expected in TAGGED_BLOBS.items():
            blob_errors, payload = _validate_tagged_blob(relative_path, expected, workspace_root)
            errors.extend(blob_errors)
            if payload is not None:
                tagged_payloads[relative_path] = payload
        if ARCHIVE_PATH in tagged_payloads and SIDECAR_PATH in tagged_payloads:
            errors.extend(
                validate_archive_sidecar(
                    tagged_payloads[ARCHIVE_PATH], tagged_payloads[SIDECAR_PATH], "tagged v0.7.0"
                )
            )
        release_manifest = tagged_payloads.get("artifacts/v0.7/release-qualification.json")
        if release_manifest is not None:
            errors.extend(_validate_release_manifest(release_manifest))

        for relative_path, expected in TRACKED_SOURCE_INPUTS.items():
            blob_errors, payload = _validate_tagged_blob(relative_path, expected, workspace_root)
            errors.extend(blob_errors)
            try:
                current = _read_regular_file(
                    workspace_root / relative_path, 8 * 1024 * 1024, f"source input {relative_path}"
                )
                if payload is not None and current != payload:
                    errors.append(f"workspace source input differs from v0.7.0: {relative_path}")
            except (OSError, ValueError) as exc:
                errors.append(f"cannot validate workspace source input {relative_path}: {exc}")

        try:
            workspace_archive = _read_regular_file(
                workspace_root / ARCHIVE_PATH, 256 * 1024 * 1024, "v0.7 archive"
            )
            workspace_sidecar = _read_regular_file(
                workspace_root / SIDECAR_PATH, 1024, "v0.7 archive sidecar"
            )
            errors.extend(validate_archive_sidecar(workspace_archive, workspace_sidecar, "workspace v0.7.0"))
            if tagged_payloads.get(ARCHIVE_PATH) != workspace_archive:
                errors.append("workspace v0.7 archive differs from accepted tagged blob")
            if tagged_payloads.get(SIDECAR_PATH) != workspace_sidecar:
                errors.append("workspace v0.7 sidecar differs from accepted tagged blob")
        except (OSError, ValueError) as exc:
            errors.append(f"cannot validate workspace v0.7 artifact pair: {exc}")

        for relative_path, expected in EXTERNAL_AUTHORITIES.items():
            try:
                raw = _read_regular_file(
                    workspace_root / relative_path,
                    int(expected["size"]),
                    f"external authority {relative_path}",
                )
                if len(raw) != expected["size"]:
                    errors.append(f"external authority byte count differs: {relative_path}")
                if sha256_bytes(raw) != expected["sha256"]:
                    errors.append(f"external authority SHA-256 differs: {relative_path}")
            except (OSError, ValueError) as exc:
                errors.append(f"cannot validate external authority {relative_path}: {exc}")

        for relative_path in POST_BASELINE_ONLY_PATHS:
            listing = run_git(
                ["ls-tree", "-r", "--name-only", "-z", PEELED_RELEASE_COMMIT, "--", relative_path],
                workspace_root,
            ).stdout
            if any(listing.split(b"\0")):
                errors.append(f"v0.8 Gate 0A path unexpectedly exists in v0.7.0: {relative_path}")
            current_path = workspace_root / Path(relative_path)
            if not current_path.is_file() or current_path.is_symlink():
                errors.append(f"v0.8 Gate 0A path is missing or not a regular file: {relative_path}")

        final_ref = _single_ascii_line(
            run_git(["show-ref", "--verify", "--hash", TAG_REF], workspace_root).stdout,
            f"final {TAG_REF}",
        )
        if final_ref != initial_ref:
            errors.append("refs/tags/v0.7.0 changed during validation")
    except GitValidationError as exc:
        errors.append(str(exc))
    return errors


def validate_document_lines(lines: list[str]) -> list[str]:
    errors: list[str] = []
    title = "# SPELL v0.8 Pre-Implementation Gate 0A"
    first_nonempty = next((line for line in lines if line.strip()), None)
    if first_nonempty != title or lines.count(title) != 1:
        errors.append("SPELL v0.8 Gate 0A title differs")
    required_lines = (
        "| Gate status | `PASS`; `V08-DATA-001` through `V08-DATA-009` are authorized |",
        "| Owner approval date | 2026-08-17 |",
        f"| Owner request | `{OWNER_REQUEST}` |",
        "| Authorized work packages | `V08-DATA-001` through `V08-DATA-009` |",
        "| Scope profile | `LOCAL_SYNTHETIC_NON_CUI_DATA_SERVICE` |",
        "| Raw tag-object SHA-256 | `dfa9c0c68cd3c9f3a64768392c001a66b1641e31dcae1ffd5bf2c40197838cae` |",
        "| Accepted `artifacts/v0.7` tree | `b6b4a9239e36eaea61da8e7d87cc5bffecfd064f` |",
        "`V08-GATE-0A PASS` authorizes implementation of exactly `V08-DATA-001` through",
        "`V08-DATA-009`. It claims zero implemented constructs and zero implemented",
        PASS_MARKER,
        OWNER_APPROVAL_MARKER,
    )
    for marker in required_lines:
        count = lines.count(marker)
        if count != 1:
            errors.append(f"accepted Gate 0A marker {marker!r} occurs {count} times, expected 1")
    for index in range(1, 10):
        work_package_id = f"V08-DATA-{index:03d}"
        if not any(line.startswith(f"| `{work_package_id}` |") for line in lines):
            errors.append(f"proposal table is missing {work_package_id}")
    for name, digest in CONTRACTS_SHA256.items():
        marker = f"| `contracts/v08/{name}` | `{digest}` |"
        if lines.count(marker) != 1:
            errors.append(f"proposal contract binding differs: {name}")
    if any("PENDING_CONTRACT_SHA256" in line for line in lines):
        errors.append("proposal contains a pending contract hash")
    return errors


def validate_document(workspace_root: Path = WORKSPACE_ROOT) -> list[str]:
    path = workspace_root / PROPOSAL_PATH
    try:
        raw = _read_regular_file(path, 512 * 1024, "SPELL v0.8 Gate 0A record")
        lines = raw.decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return [f"cannot read SPELL v0.8 Gate 0A record: {exc}"]
    return validate_document_lines(lines)


def validate_repository(
    scope_path: Path = SCOPE_PATH,
    workspace_root: Path = WORKSPACE_ROOT,
) -> tuple[list[str], dict[str, Any]]:
    try:
        payload = read_json(scope_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors = [f"cannot load Gate 0A scope: {exc}"]
        return errors, _scope_summary(None, False)
    errors, summary = validate_scope_payload(payload)
    errors.extend(validate_git_baseline(workspace_root))
    errors.extend(validate_contract_directory(workspace_root / CONTRACT_DIRECTORY))
    errors.extend(validate_compatibility_selection(workspace_root))
    errors.extend(validate_document(workspace_root))
    summary["gate"] = "PASS" if not errors else "FAIL"
    return errors, summary


def main() -> int:
    errors, summary = validate_repository()
    if errors:
        print(
            "gate=FAIL "
            f"authorized_work_packages={summary['authorized_work_packages']} "
            f"proposed_work_packages={summary['proposed_work_packages']} "
            f"claimed_constructs={summary['claimed_constructs']} "
            f"claimed_artifacts={summary['claimed_artifacts']}"
        )
        for error in errors[:75]:
            print(f"ERROR: {error}", file=sys.stderr)
        if len(errors) > 75:
            print(f"ERROR: {len(errors) - 75} additional errors omitted", file=sys.stderr)
        return 1
    print(PASS_MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
