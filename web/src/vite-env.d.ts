/// <reference types="vite/client" />

/** Compile-time flag injected by vite `define`: true only in the demo build. */
declare const __DEMO__: boolean;

/** Build version injected by vite `define` (from package.json) — UI display and
 *  the demo / offline fallback when the backend `/health` version is unavailable. */
declare const __APP_VERSION__: string;
