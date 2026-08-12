# Source Authority And Evidence Manifest

## Reviewed Source Set

The supplied source directory is `../SPELL-DOCUMENTATION/` (hyphenated on disk).
The page-complete review is recorded in
[`../SPELL_DOCUMENTATION_REVIEW.md`](../SPELL_DOCUMENTATION_REVIEW.md). The seven
files total 304 pages and were reviewed page by page.

| Source | Pages | SHA-256 | Authority in this specification |
| --- | ---: | --- | --- |
| [SPELL - Language Reference - 2.4.4.pdf](../SPELL-DOCUMENTATION/SPELL%20-%20Language%20Reference%20-%202.4.4.pdf) | 118 | `ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3` | Authoritative language semantics and public vocabulary; preserve unchanged except separately approved errata |
| [SPELL - Driver Development Manual - 2.4.4.pdf](../SPELL-DOCUMENTATION/SPELL%20-%20Driver%20Development%20Manual%20-%202.4.4.pdf) | 45 | `057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5` | Authoritative driver service intent and interface vocabulary; preserve unchanged except separately approved errata |
| [SPELL - GUI User Manual - 2.4.4.pdf](../SPELL-DOCUMENTATION/SPELL%20-%20GUI%20User%20Manual%20-%202.4.4.pdf) | 54 | `1a6b13190b0bb25d6f19a0549f3917beaac72a40d851eac5165a95c9d3b779c6` | Legacy operator behavior and workflow evidence; redesigned for the web and modern security |
| [SPELL - Development Environment Manual - 2.4.4.pdf](../SPELL-DOCUMENTATION/SPELL%20-%20Development%20Environment%20Manual%20-%202.4.4.pdf) | 57 | `cedf617a4d551701394f75a8ec1769a402059a4c7b659ed87079ce5148074a81` | Legacy authoring, dictionaries, semantic analysis, and collaboration evidence; Git/web workflow replaces Eclipse/CVS/SVN |
| [SPELL - Server Manual - 2.4.4.pdf](../SPELL-DOCUMENTATION/SPELL%20-%20Server%20Manual%20-%202.4.4.pdf) | 11 | `ee123aaf6434ec781e9f2679729207d138f775ba99175ae7310558b98ca4dcb9` | Legacy listener, context, executor, configuration, and driver-selection evidence |
| [SPELL - Build Manual - 2.4.4.pdf](../SPELL-DOCUMENTATION/SPELL%20-%20Build%20Manual%20-%202.4.4.pdf) | 16 | `6ab753a3c8b07465e92a48ab8c1ab28693062942a456ac540c80baac7e17e9e6` | Historical component/build/package evidence; obsolete tool choices are non-binding |
| [SPELL-GUI-4.0.2-Build-Instructions.pdf](../SPELL-DOCUMENTATION/SPELL-GUI-4.0.2-Build-Instructions.pdf) | 3 | `5d8c93bec655499b42f921336640c42eb9dcd68f8979eced3e74758aef71dba6` | Historical GUI packaging evidence only |

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
   this repository are authoritative. Local v0.4 uses only the manifest-bound
   Candidate A technical gate; proposed broader ADRs and organization decisions
   do not become local approval requirements.
4. For legacy behavior outside the two core manuals, reproducible, approved,
   version-specific traces outrank implementation inference; version-specific
   source then outranks other legacy manuals.
5. Unresolved conflicts are recorded in the compatibility ledger or open-decision
   register. Implementations shall not guess.

Modern security controls may constrain how an authoritative language or driver
concept is exposed. They shall preserve observable intent where possible and
shall document any deliberate incompatibility with a stable diagnostic and
migration path.

## Preservation Policy

The two core PDFs are not duplicated into this generated repository. Their exact
external bytes are identified by title, location, version, size-independent
SHA-256 digest, and authority record under `preserved/`. This avoids an implied
redistribution decision and prevents editorial modernization from changing the
normative source.

After legal and configuration-management approval, an organization may vendor
the exact files into an immutable evidence store. Vendoring shall preserve the
recorded digests and shall not convert, optimize, annotate, or re-save them.

## Integrity Verification

From the parent repository, the evidence can be checked with:

```powershell
Get-ChildItem -LiteralPath .\SPELL-DOCUMENTATION -Filter *.pdf |
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
