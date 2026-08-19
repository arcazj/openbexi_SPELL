# Language Reference Authority Record

## Immutable Authority

| Field | Value |
| --- | --- |
| Title | SPELL - Language Reference - Version 2.4.4 |
| Local evidence | [SPELL - Language Reference - 2.4.4.pdf](../../SPELL_DOCUMENTATION/SPELL%20-%20Language%20Reference%20-%202.4.4.pdf) |
| Pages reviewed | 118 of 118 |
| SHA-256 | `ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3` |
| Authority domain | Language syntax, public functions, modifiers, constants, results, actions, and procedure-visible semantics |
| Editorial state | Unchanged versioned source reference |
| Product packaging | Excluded |

This PDF remains the authoritative definition of the SPELL language baseline.
The generated documentation does not rewrite it. Python 2 examples, ambiguous
wording, errata, or behavior that cannot be safely exposed in the modern runtime
shall be handled through an additive compatibility disposition; they shall not
be silently edited out of the authority.

## Modernization Boundary

The modern implementation may replace the execution mechanism while preserving
procedure-visible intent. It shall parse an approved source profile into bounded,
versioned, data-only IR and shall not execute arbitrary Python modules, shell
commands, text evaluation, or direct network/file/driver access.

Each accepted exact behavior, safe strengthening, legacy syntax translation,
optional adapter capability, deliberate rejection, and confirmed documentation
ambiguity shall be recorded in
[`../requirements/COMPATIBILITY_LEDGER.md`](../requirements/COMPATIBILITY_LEDGER.md).
An unsupported construct shall fail validation with stable code, source range,
explanation, and migration guidance.

## Change Protection

- The referenced bytes shall not be modified or re-saved.
- A replacement source version requires a new authority record and full review.
- Errata shall identify page, exact concept, evidence, compatibility impact,
  decision owner, and conformance tests.
- A safety or security deviation requires language, mission-operations, security,
  architecture, and quality review as applicable.
