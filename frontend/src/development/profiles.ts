export const LEGACY_LANGUAGE_PROFILE = "spell-restricted-ast/0.9" as const;
export const V19_LANGUAGE_PROFILE = "spell-lrm244-conformance/0.19" as const;
export type AuthoringProfile = typeof LEGACY_LANGUAGE_PROFILE | typeof V19_LANGUAGE_PROFILE;
