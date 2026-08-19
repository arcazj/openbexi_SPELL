# Source Authority And Evidence Manifest

## Forward-Work Reference Policy

Every document present under the parent repository's
`../SPELL_DOCUMENTATION/` directory is a mandatory source-reference input for
future SPELL planning, coding, testing, integration, and delivery. Generated
requirements and designs in this directory are controlled interpretations of
those sources; they do not independently supersede them. Every implemented
behavior, safety strengthening, migration, exclusion, or unsupported result
must retain traceability to the applicable source identity and an explicit
compatibility or architecture decision.

The source-reference role is distinct from implementation and release
authority. Versioned code and tests establish implemented behavior, and
validated annotated tags establish accepted release status. The manuals do not
authorize copying legacy implementation code, product packaging, live
connectivity, deployment, compliance, or operational use.

## Reviewed Source Set

The historical page-complete review is recorded in
[`../SPELL_DOCUMENTATION_REVIEW.md`](../SPELL_DOCUMENTATION_REVIEW.md). Its
seven-file set totals 304 pages and was reviewed page by page. Five behavioral
manuals from that set are now versioned under `../SPELL_DOCUMENTATION/`. The
Build Manual and GUI build instructions remain identified historical evidence
but are not currently versioned in that directory.

| Source | Pages | SHA-256 | Authority in this specification |
| --- | ---: | --- | --- |
| [SPELL - Language Reference - 2.4.4.pdf](../SPELL_DOCUMENTATION/SPELL%20-%20Language%20Reference%20-%202.4.4.pdf) | 118 | `ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3` | Authoritative language semantics and public vocabulary; preserve unchanged except separately approved errata |
| [SPELL - Driver Development Manual - 2.4.4.pdf](../SPELL_DOCUMENTATION/SPELL%20-%20Driver%20Development%20Manual%20-%202.4.4.pdf) | 45 | `057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5` | Authoritative driver service intent and interface vocabulary; preserve unchanged except separately approved errata |
| [SPELL - GUI User Manual - 2.4.4.pdf](../SPELL_DOCUMENTATION/SPELL%20-%20GUI%20User%20Manual%20-%202.4.4.pdf) | 54 | `1a6b13190b0bb25d6f19a0549f3917beaac72a40d851eac5165a95c9d3b779c6` | Operator behavior and workflow reference; implementation is redesigned for the web and modern security |
| [SPELL - Development Environment Manual - 2.4.4.pdf](../SPELL_DOCUMENTATION/SPELL%20-%20Development%20Environment%20Manual%20-%202.4.4.pdf) | 57 | `cedf617a4d551701394f75a8ec1769a402059a4c7b659ed87079ce5148074a81` | Authoring, dictionaries, semantic analysis, and collaboration reference; Git/web workflow replaces Eclipse/CVS/SVN |
| [SPELL - Server Manual - 2.4.4.pdf](../SPELL_DOCUMENTATION/SPELL%20-%20Server%20Manual%20-%202.4.4.pdf) | 11 | `ee123aaf6434ec781e9f2679729207d138f775ba99175ae7310558b98ca4dcb9` | Listener, context, executor, configuration, and driver-selection reference |
| `SPELL - Build Manual - 2.4.4.pdf` | 16 | `6ab753a3c8b07465e92a48ab8c1ab28693062942a456ac540c80baac7e17e9e6` | Reviewed historical build evidence; not currently versioned under `SPELL_DOCUMENTATION/` |
| `SPELL-GUI-4.0.2-Build-Instructions.pdf` | 3 | `5d8c93bec655499b42f921336640c42eb9dcd68f8979eced3e74758aef71dba6` | Reviewed historical GUI packaging evidence; not currently versioned under `SPELL_DOCUMENTATION/` |

## Supplementary Versioned Manuals

The following earlier manuals are also mandatory references because they are
present under `SPELL_DOCUMENTATION/`. They supplement the later 2.4.4 manuals
and are not included in the historical 304-page total. When versions conflict,
the applicable later source controls unless an approved compatibility decision
states otherwise.

| Source | Pages | SHA-256 | Reference use |
| --- | ---: | --- | --- |
| [SPELL_Language_Manual.pdf](../SPELL_DOCUMENTATION/SPELL_Language_Manual.pdf) | 68 | `f2f3e72e62692eeabb287b704878240012062f894b52a10570b8f42199c233fb` | Earlier language terminology, behavior, and change-history reference |
| [SPELL_DEV_Manual.pdf](../SPELL_DOCUMENTATION/SPELL_DEV_Manual.pdf) | 37 | `94c1443646e22f3692ac25d2ef570ff437d83c38b71082e7077b4a322e5fb94f` | Earlier development-environment workflow and change-history reference |

## Domain-Specific Precedence

There is no single precedence rule for unrelated domains. Apply these rules:

1. For language syntax, functions, modifiers, results, and procedure-visible
   semantics, the Language Reference 2.4.4 is authoritative. A confirmed erratum
   or safety deviation requires a compatibility-ledger row, planned test,
   decision, and scope disposition. For the local-only synthetic non-CUI v0.4
   gate, the project-owner Candidate A/exclusion policy plus independent
   technical validation supplies that disposition; language/mission authority
   approval applies only to a later scope that makes such behavior executable
   or connected.
2. For driver service intent, lifecycle vocabulary, and GCS-independent public
   concepts, the Driver Development Manual 2.4.4 is authoritative. Its legacy
   in-process inheritance, Python 2 assumptions, weak typing, and transport
   implementation are not target constraints.
3. For the new architecture, security boundary, protocols, data ownership,
   deployment, reliability, and web design, approved requirements and ADRs in
   this repository define the controlled modern interpretation. They must trace
   to the source references and explicitly record any deliberate incompatibility.
   Local v0.4 uses only the manifest-bound Candidate A technical gate; proposed
   broader ADRs and organization decisions do not become local approval
   requirements.
4. Reproducible, approved, version-specific traces may establish what a legacy
   binary actually did, but they do not silently erase documented forward
   behavior. Reconcile discrepancies through an explicit compatibility record.
5. Unresolved conflicts are recorded in the compatibility ledger or open-decision
   register. Implementations shall not guess.

Modern security controls may constrain how an authoritative language or driver
concept is exposed. They shall preserve observable intent where possible and
shall document any deliberate incompatibility with a stable diagnostic and
migration path.

## Preservation Policy

The reference PDFs are stored unchanged under the parent repository's
`SPELL_DOCUMENTATION/` directory and are not duplicated into this generated
documentation tree or product packages. Their exact bytes are identified by
title, location, version, and SHA-256 digest. Replacement, conversion,
optimization, annotation, or re-saving requires a new inventory, review, and
controlled baseline decision.

## Integrity Verification

From the parent repository, the evidence can be checked with:

```powershell
Get-ChildItem -LiteralPath .\SPELL_DOCUMENTATION -Filter *.pdf |
  Get-FileHash -Algorithm SHA256 |
  Sort-Object Path
```

A digest mismatch invalidates the source review for that file until the new bytes
are inventoried, reviewed, and accepted as a different source version.

## External Standards

The security baseline references official NIST publications rather than local
copies:

- [NIST SP 800-171 Rev. 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final)
- [NIST SP 800-171A Rev. 3](https://csrc.nist.gov/pubs/sp/800/171/a/r3/final)
- [NIST SP 800-172 Rev. 3](https://csrc.nist.gov/pubs/sp/800/172/r3/final)
- [NIST CUI publications](https://csrc.nist.gov/Projects/protecting-controlled-unclassified-information/publications)
- [NIST CPRT catalog](https://csrc.nist.gov/projects/cprt/catalog)
- [W3C Web Content Accessibility Guidelines 2.2](https://www.w3.org/TR/WCAG22/)

Applicability, organization-defined parameters (ODPs), contract clauses, CUI
categories, assessment depth, and enhanced requirements shall be resolved by the
accountable organization. A citation does not itself satisfy a requirement.
