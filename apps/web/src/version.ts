// Build stamp substituted by Vite's `define` (see apps/web/vite.config.ts).
//
// The `typeof` guards matter: the unit suite compiles this module with tsc and runs it
// under plain node, where the identifiers were never substituted and a bare reference
// would throw ReferenceError. Vite replaces the identifier textually, so under a real
// build the guard folds to `typeof "v0.1.0" === "string"` and the fallback drops out.
declare const __HIMITSU_VERSION__: string;
declare const __HIMITSU_COMMIT__: string;

export const APP_VERSION: string = typeof __HIMITSU_VERSION__ === "string" ? __HIMITSU_VERSION__ : "dev";
export const APP_COMMIT: string = typeof __HIMITSU_COMMIT__ === "string" ? __HIMITSU_COMMIT__ : "unknown";

/** Single-line build identity, e.g. "v0.1.0 · a1b2c3d". Rendered in the sign-in and workspace footers. */
export const BUILD_LABEL = `${APP_VERSION} · ${APP_COMMIT}`;
