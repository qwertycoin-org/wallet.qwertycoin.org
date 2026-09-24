/* tslint:disable */
/* eslint-disable */

export function qwc_qms_wasm_abi_version(): number;

export function qwc_qms_wasm_engine_new(): Uint8Array;

export function qwc_qms_wasm_prepare_contact_package(state: Uint8Array, genesis: Uint8Array): Uint8Array;

export function qwc_qms_wasm_prepare_import_contact(state: Uint8Array, local_invitation_id: Uint8Array, remote_package: Uint8Array, now_unix_seconds: number): Uint8Array;

export function qwc_qms_wasm_prepare_receive_text(state: Uint8Array, contact_id: string, message_type: number, ciphertext: Uint8Array): Uint8Array;

export function qwc_qms_wasm_prepare_send_text(state: Uint8Array, contact_id: string, text: string, now_unix_seconds: number): Uint8Array;

export function qwc_qms_wasm_transport_context(state: Uint8Array, contact_id: string, outgoing: boolean): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly qwc_qms_crypto_abi_version: () => number;
    readonly qwc_qms_crypto_buffer_free: (a: number) => void;
    readonly qwc_qms_crypto_engine_new: (a: number, b: number) => number;
    readonly qwc_qms_crypto_prepare_contact_package: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly qwc_qms_crypto_prepare_import_contact: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number) => number;
    readonly qwc_qms_crypto_prepare_receive_text: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => number;
    readonly qwc_qms_crypto_prepare_send_text: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number) => number;
    readonly qwc_qms_crypto_transport_context: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
    readonly qwc_qms_wasm_abi_version: () => number;
    readonly qwc_qms_wasm_engine_new: () => [number, number, number, number];
    readonly qwc_qms_wasm_prepare_contact_package: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly qwc_qms_wasm_prepare_import_contact: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly qwc_qms_wasm_prepare_receive_text: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly qwc_qms_wasm_prepare_send_text: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly qwc_qms_wasm_transport_context: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
