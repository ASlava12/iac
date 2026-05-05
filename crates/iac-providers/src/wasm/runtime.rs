//! Phase 7dc: wasmtime-backed plugin runtime.
//!
//! ### Plugin ABI (v1)
//!
//! A WASM plugin must export:
//!
//! * `memory: memory` — its linear memory (mandatory; the host writes
//!   request bytes here and reads response bytes back).
//! * `iac_alloc(size: i32) -> i32` — allocate `size` bytes; return ptr.
//!   The host calls this once per request to stage the JSON envelope.
//! * `iac_dealloc(ptr: i32, size: i32)` — free a buffer the host
//!   allocated via `iac_alloc`. Used when freeing input AND when
//!   freeing the response after copying it out.
//! * `iac_kind() -> i64` — return packed `(ptr << 32) | len` of a
//!   UTF-8 string giving the plugin's resource kind. Validated against
//!   the agent's config; mismatch fails the spawn.
//! * `iac_observe(ptr: i32, len: i32) -> i64` — required.
//! * `iac_apply(ptr: i32, len: i32) -> i64` — required.
//!
//! Optional, opt-in via `iac_methods() -> i64` (returns a JSON-array
//! string of method names): `iac_diff`, `iac_verify`, `iac_rollback`,
//! `iac_pre_apply`. Empty / missing means "host falls back".
//!
//! ### Sandbox model
//!
//! No WASI by default — guest sees no filesystem, env, sockets. CPU
//! is bounded by [`Engine::consume_fuel`]; memory by a
//! [`ResourceLimiter`] that hard-rejects growth past the configured
//! cap. Each top-level method call uses a fresh [`Store`] with a
//! fresh fuel budget so a previous call's overrun can't poison the
//! next one.

use super::spec::WasmProviderSpec;
#[cfg(test)]
use super::spec::WasmRuntimeKind;
use iac_core::{Error, Result};
use parking_lot::Mutex;
use wasmtime::{Caller, Config, Engine, Instance, Linker, Module, ResourceLimiter, Store};

/// Per-plugin runtime: an [`Engine`], the compiled [`Module`], and a
/// cached `iac_kind` string captured at first instantiation.
pub struct WasmRuntime {
    spec: WasmProviderSpec,
    engine: Engine,
    module: Module,
    /// Filled in on the first successful call. Re-validated against
    /// `spec.kind` so a runtime swap to a different binary is caught.
    kind_cache: Mutex<Option<String>>,
}

/// Per-call host state. Lives in the wasmtime [`Store`] so host
/// functions (currently none beyond resource limiting) can read it
/// during execution.
struct CallState {
    limiter: MemoryLimiter,
}

struct MemoryLimiter {
    max_bytes: usize,
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, anyhow::Error> {
        Ok(desired <= self.max_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, anyhow::Error> {
        Ok(true)
    }
}

impl WasmRuntime {
    pub fn new(spec: WasmProviderSpec) -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        // Threads are off by default in wasmtime. SIMD stays on:
        // wasmtime 26 refuses to disable SIMD without also disabling
        // relaxed-SIMD (it's a coupled pair), and CRUD-shaped plugins
        // aren't a profitable target for SIMD-shaped attacks anyway.
        let engine = Engine::new(&config).map_err(|e| {
            Error::provider(&spec.kind, format!("wasmtime engine init: {e}"))
        })?;
        let bytes = std::fs::read(&spec.module).map_err(|e| {
            Error::provider(
                &spec.kind,
                format!("read module {}: {e}", spec.module.display()),
            )
        })?;
        // Phase 7dh.4: verify content-hash pin BEFORE compiling.
        // If the binary on disk has been swapped, this is the only
        // gate that catches it — wasmtime would happily compile a
        // malicious-but-well-formed module otherwise.
        if let Some(expected) = spec.module_sha256.as_deref() {
            super::spec::verify_sha256(&bytes, expected, "module").map_err(|e| {
                Error::provider(&spec.kind, e)
            })?;
        }
        let module = Module::new(&engine, &bytes).map_err(|e| {
            Error::provider(
                &spec.kind,
                format!("compile module {}: {e}", spec.module.display()),
            )
        })?;
        Ok(Self {
            spec,
            engine,
            module,
            kind_cache: Mutex::new(None),
        })
    }

    /// Construct a runtime directly from in-memory `.wasm` bytes.
    /// Used in tests to skip the on-disk module step. Honours
    /// `spec.module_sha256` the same way the on-disk path does.
    #[cfg(test)]
    pub fn from_bytes(spec: WasmProviderSpec, bytes: &[u8]) -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(|e| {
            Error::provider(&spec.kind, format!("wasmtime engine init: {e}"))
        })?;
        if let Some(expected) = spec.module_sha256.as_deref() {
            super::spec::verify_sha256(bytes, expected, "module").map_err(|e| {
                Error::provider(&spec.kind, e)
            })?;
        }
        let module = Module::new(&engine, bytes).map_err(|e| {
            Error::provider(&spec.kind, format!("compile module: {e}"))
        })?;
        Ok(Self {
            spec,
            engine,
            module,
            kind_cache: Mutex::new(None),
        })
    }

    pub fn kind(&self) -> &str {
        &self.spec.kind
    }

    pub fn cached_kind(&self) -> Option<String> {
        self.kind_cache.lock().clone()
    }

    fn fresh_store(&self) -> Store<CallState> {
        let mut store = Store::new(
            &self.engine,
            CallState {
                limiter: MemoryLimiter {
                    max_bytes: usize::try_from(self.spec.max_memory_bytes)
                        .unwrap_or(usize::MAX),
                },
            },
        );
        store.limiter(|s| &mut s.limiter);
        // SAFETY: set_fuel can only fail if `consume_fuel` was disabled
        // on the engine config. We enabled it above.
        let _ = store.set_fuel(self.spec.fuel_per_call);
        store
    }

    fn instantiate(&self, store: &mut Store<CallState>) -> Result<Instance> {
        let mut linker: Linker<CallState> = Linker::new(&self.engine);
        // Phase 7dc: deliberately empty host imports. Plugins that
        // need I/O are the wrong fit for WASM — use the
        // external-process variant instead. We provide one helper
        // import: `iac_log(ptr, len)` so plugins can emit operator-
        // visible diagnostics through the agent's tracing pipeline.
        let kind_for_log = self.spec.kind.clone();
        linker
            .func_wrap(
                "iac",
                "log",
                move |mut caller: Caller<'_, CallState>, ptr: i32, len: i32| {
                    if let Ok(s) = read_string(&mut caller, ptr, len) {
                        tracing::info!(
                            target: "iac_providers::wasm",
                            kind = %kind_for_log,
                            "{s}"
                        );
                    }
                },
            )
            .map_err(|e| {
                Error::provider(&self.spec.kind, format!("link iac.log: {e}"))
            })?;
        linker
            .instantiate(&mut *store, &self.module)
            .map_err(|e| Error::provider(&self.spec.kind, format!("instantiate: {e}")))
    }

    /// Validate that the module's `iac_kind` export agrees with the
    /// configured kind. Cheap to call repeatedly; runs at most once
    /// because we cache the result.
    pub fn validate_kind(&self) -> Result<()> {
        if self.kind_cache.lock().is_some() {
            return Ok(());
        }
        let mut store = self.fresh_store();
        let instance = self.instantiate(&mut store)?;
        let func = instance
            .get_typed_func::<(), i64>(&mut store, "iac_kind")
            .map_err(|e| {
                Error::provider(&self.spec.kind, format!("missing iac_kind: {e}"))
            })?;
        let packed = func
            .call(&mut store, ())
            .map_err(|e| Error::provider(&self.spec.kind, format!("iac_kind: {e}")))?;
        let (ptr, len) = unpack(packed);
        let mut caller_like = StoreCaller(&mut store);
        let kind = read_string_from_instance(&mut caller_like, &instance, ptr, len)?;
        if kind != self.spec.kind {
            return Err(Error::provider(
                &self.spec.kind,
                format!(
                    "module reports kind={kind:?}, config expects {:?}",
                    self.spec.kind
                ),
            ));
        }
        *self.kind_cache.lock() = Some(kind);
        Ok(())
    }

    /// Read the optional `iac_methods` export. Returns the parsed
    /// list of method names a plugin opts into beyond the required
    /// pair, or an empty list when the export is absent / empty.
    pub fn read_methods(&self) -> Result<Vec<String>> {
        let mut store = self.fresh_store();
        let instance = self.instantiate(&mut store)?;
        let Ok(func) = instance.get_typed_func::<(), i64>(&mut store, "iac_methods")
        else {
            return Ok(Vec::new());
        };
        let packed = func
            .call(&mut store, ())
            .map_err(|e| Error::provider(&self.spec.kind, format!("iac_methods: {e}")))?;
        let (ptr, len) = unpack(packed);
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut caller = StoreCaller(&mut store);
        let s = read_string_from_instance(&mut caller, &instance, ptr, len)?;
        serde_json::from_str(&s).map_err(|e| {
            Error::provider(&self.spec.kind, format!("iac_methods: bad json: {e}: {s:?}"))
        })
    }

    /// Call a `(ptr, len) -> packed_ptr_len` plugin export with `input`
    /// as JSON bytes. Returns the response JSON as a `String`.
    pub fn call(&self, method: &str, input: &[u8]) -> Result<String> {
        let export_name = format!("iac_{method}");
        let mut store = self.fresh_store();
        let instance = self.instantiate(&mut store)?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "iac_alloc")
            .map_err(|e| {
                Error::provider(&self.spec.kind, format!("missing iac_alloc: {e}"))
            })?;
        let dealloc = instance
            .get_typed_func::<(i32, i32), ()>(&mut store, "iac_dealloc")
            .map_err(|e| {
                Error::provider(&self.spec.kind, format!("missing iac_dealloc: {e}"))
            })?;
        let target = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, &export_name)
            .map_err(|e| {
                Error::provider(
                    &self.spec.kind,
                    format!("missing {export_name}: {e}"),
                )
            })?;

        let in_len = i32::try_from(input.len()).map_err(|_| {
            Error::provider(&self.spec.kind, "input larger than i32::MAX")
        })?;
        let in_ptr = alloc.call(&mut store, in_len).map_err(|e| {
            Error::provider(
                &self.spec.kind,
                format!("iac_alloc({in_len}): {e}"),
            )
        })?;
        write_bytes(&instance, &mut store, in_ptr, input)?;

        let packed = target.call(&mut store, (in_ptr, in_len)).map_err(|e| {
            Error::provider(
                &self.spec.kind,
                format!("{export_name}: {e}"),
            )
        })?;
        // Free the input buffer (response is the plugin's
        // responsibility — we copy out then free below).
        let _ = dealloc.call(&mut store, (in_ptr, in_len));
        let (out_ptr, out_len) = unpack(packed);
        // Borrow `store` mutably through `StoreCaller` only for the
        // duration of the read; the `{ ... }` block ends the borrow
        // before we re-enter wasm via `dealloc.call`. (Pre-cleanup
        // this used `drop(caller)`, but `StoreCaller` doesn't impl
        // `Drop` — a scope is the idiomatic way.)
        let resp = {
            let mut caller = StoreCaller(&mut store);
            read_string_from_instance(&mut caller, &instance, out_ptr, out_len)?
        };
        let _ = dealloc.call(&mut store, (out_ptr, i32::try_from(out_len).unwrap_or(0)));
        Ok(resp)
    }
}

// ---- shared memory helpers ------------------------------------------------

fn unpack(packed: i64) -> (i32, u32) {
    let p = ((packed as u64) >> 32) as u32;
    let l = (packed as u64 & 0xFFFF_FFFF) as u32;
    (p as i32, l)
}

/// Helper that lets `read_string_from_instance` operate against either
/// a wasmtime [`Caller`] (during a host call) or a [`Store`] reference
/// (when the host orchestrates an export call).
trait StoreLike {
    fn memory_bytes(&mut self, instance: &Instance) -> Option<&[u8]>;
}

struct StoreCaller<'a>(&'a mut Store<CallState>);

impl<'a> StoreLike for StoreCaller<'a> {
    fn memory_bytes(&mut self, instance: &Instance) -> Option<&[u8]> {
        let mem = instance.get_memory(&mut *self.0, "memory")?;
        Some(mem.data(&self.0))
    }
}

fn read_string_from_instance(
    store: &mut dyn StoreLike,
    instance: &Instance,
    ptr: i32,
    len: u32,
) -> Result<String> {
    let bytes = store
        .memory_bytes(instance)
        .ok_or_else(|| Error::provider("wasm", "module missing `memory` export"))?;
    let start = usize::try_from(ptr).map_err(|_| {
        Error::provider("wasm", format!("negative ptr {ptr} returned by guest"))
    })?;
    let len_us = len as usize;
    let end = start
        .checked_add(len_us)
        .ok_or_else(|| Error::provider("wasm", "ptr+len overflows usize"))?;
    if end > bytes.len() {
        return Err(Error::provider(
            "wasm",
            format!("string ptr={ptr} len={len} OOB (mem={})", bytes.len()),
        ));
    }
    String::from_utf8(bytes[start..end].to_vec())
        .map_err(|e| Error::provider("wasm", format!("not utf-8: {e}")))
}

/// Phase 7dh.2: hard cap on guest-controlled `iac.log` payloads.
/// Before this, `len` was an i32 the guest fully controlled — a
/// malicious plugin could request a 2 GiB allocation on every log
/// call to OOM the agent. 64 KiB is plenty for diagnostic strings;
/// anything bigger is either a bug or an attack and gets truncated
/// with an explicit marker so operators see what happened.
const MAX_GUEST_LOG_BYTES: usize = 64 * 1024;

/// Read a string from a host import context. Used by `iac.log`.
fn read_string(
    caller: &mut Caller<'_, CallState>,
    ptr: i32,
    len: i32,
) -> Result<String> {
    let mem = caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| Error::provider("wasm", "host import: memory missing"))?;
    let len_us = usize::try_from(len)
        .map_err(|_| Error::provider("wasm", "negative log len"))?;
    let start = usize::try_from(ptr)
        .map_err(|_| Error::provider("wasm", "negative log ptr"))?;
    // Truncate before allocating — never reserve more than the cap.
    let (effective_len, truncated) = if len_us > MAX_GUEST_LOG_BYTES {
        (MAX_GUEST_LOG_BYTES, true)
    } else {
        (len_us, false)
    };
    let mut buf = vec![0u8; effective_len];
    mem.read(&mut *caller, start, &mut buf)
        .map_err(|e| Error::provider("wasm", format!("log read: {e}")))?;
    let mut s = String::from_utf8(buf)
        .map_err(|e| Error::provider("wasm", format!("log not utf-8: {e}")))?;
    if truncated {
        s.push_str("…[iac.log: truncated; plugin requested ");
        s.push_str(&len_us.to_string());
        s.push_str(" bytes, host caps at ");
        s.push_str(&MAX_GUEST_LOG_BYTES.to_string());
        s.push(']');
    }
    Ok(s)
}

fn write_bytes(
    instance: &Instance,
    store: &mut Store<CallState>,
    ptr: i32,
    bytes: &[u8],
) -> Result<()> {
    let mem = instance
        .get_memory(&mut *store, "memory")
        .ok_or_else(|| Error::provider("wasm", "module missing `memory` export"))?;
    let start = usize::try_from(ptr).map_err(|_| {
        Error::provider("wasm", format!("negative ptr {ptr} from iac_alloc"))
    })?;
    mem.write(&mut *store, start, bytes)
        .map_err(|e| Error::provider("wasm", format!("write: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal WAT plugin: stack-bump allocator, hardcoded kind,
    /// `iac_observe` returns a fixed JSON literal regardless of input.
    /// This proves the host↔guest memory dance works end-to-end
    /// without bootstrapping a wasm32-wasi Rust toolchain.
    fn fixture_wat() -> &'static str {
        r#"
(module
  (memory (export "memory") 1)
  ;; "test.kind" at offset 16
  (data (i32.const 16) "test.kind")
  ;; observe response at offset 64
  (data (i32.const 64) "{\"present\":false}")
  ;; apply response at offset 128
  (data (i32.const 128) "{\"status\":\"ok\",\"message\":\"applied\"}")
  ;; method list at offset 256
  (data (i32.const 256) "[]")

  ;; Bump-pointer allocator. `iac_alloc(size)` returns the next free
  ;; offset starting at 4096 (above our static data area). No
  ;; freelist; `iac_dealloc` is a no-op. Plugins that grow past
  ;; one page cause memory.grow which is bounded by the host's
  ;; ResourceLimiter.
  (global $next (mut i32) (i32.const 4096))
  (func (export "iac_alloc") (param $size i32) (result i32)
    (local $ret i32)
    (local.set $ret (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $size)))
    (local.get $ret))
  (func (export "iac_dealloc") (param $ptr i32) (param $size i32)
    nop)

  (func (export "iac_kind") (result i64)
    (i64.or
      (i64.shl (i64.const 16) (i64.const 32))
      (i64.const 9)))

  (func (export "iac_observe") (param i32 i32) (result i64)
    (i64.or
      (i64.shl (i64.const 64) (i64.const 32))
      (i64.const 17)))

  (func (export "iac_apply") (param i32 i32) (result i64)
    (i64.or
      (i64.shl (i64.const 128) (i64.const 32))
      (i64.const 35)))

  (func (export "iac_methods") (result i64)
    (i64.or
      (i64.shl (i64.const 256) (i64.const 32))
      (i64.const 2)))
)
"#
    }

    fn fixture_runtime() -> WasmRuntime {
        let bytes = wat::parse_str(fixture_wat()).unwrap();
        let spec = WasmProviderSpec {
            kind: "test.kind".into(),
            module: "/dev/null".into(),
            max_memory_bytes: 16 * 1024 * 1024,
            fuel_per_call: 10_000_000,
            runtime: WasmRuntimeKind::Core,
            wasi: super::super::spec::WasiConfig::default(),
            module_sha256: None,
        };
        WasmRuntime::from_bytes(spec, &bytes).unwrap()
    }

    #[test]
    fn validate_kind_matches() {
        let rt = fixture_runtime();
        rt.validate_kind().unwrap();
        assert_eq!(rt.cached_kind().as_deref(), Some("test.kind"));
    }

    #[test]
    fn validate_kind_rejects_mismatch() {
        let bytes = wat::parse_str(fixture_wat()).unwrap();
        let spec = WasmProviderSpec {
            kind: "wrong.kind".into(),
            module: "/dev/null".into(),
            max_memory_bytes: 16 * 1024 * 1024,
            fuel_per_call: 10_000_000,
            runtime: WasmRuntimeKind::Core,
            wasi: super::super::spec::WasiConfig::default(),
            module_sha256: None,
        };
        let rt = WasmRuntime::from_bytes(spec, &bytes).unwrap();
        let err = rt.validate_kind().unwrap_err();
        assert!(format!("{err:?}").contains("test.kind"));
    }

    #[test]
    fn observe_returns_static_response() {
        let rt = fixture_runtime();
        let resp = rt.call("observe", b"{\"spec\":{\"name\":\"x\"}}").unwrap();
        assert_eq!(resp, "{\"present\":false}");
    }

    #[test]
    fn apply_returns_static_response() {
        let rt = fixture_runtime();
        let resp = rt.call("apply", b"{\"phase\":\"create\"}").unwrap();
        assert!(resp.contains("\"status\":\"ok\""));
    }

    #[test]
    fn methods_export_parses() {
        let rt = fixture_runtime();
        assert!(rt.read_methods().unwrap().is_empty());
    }

    /// Plugin that runs forever — the host's fuel limit must trap it.
    fn infinite_loop_wat() -> &'static str {
        r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 16) "test.kind")
  (global $next (mut i32) (i32.const 4096))
  (func (export "iac_alloc") (param i32) (result i32)
    (local $ret i32)
    (local.set $ret (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get 0)))
    (local.get $ret))
  (func (export "iac_dealloc") (param i32 i32) nop)
  (func (export "iac_kind") (result i64)
    (i64.or (i64.shl (i64.const 16) (i64.const 32)) (i64.const 9)))
  (func (export "iac_observe") (param i32 i32) (result i64)
    (loop $forever (br $forever))
    (i64.const 0))
  (func (export "iac_apply") (param i32 i32) (result i64)
    (i64.const 0))
)
"#
    }

    /// Phase 7dh.2 regression: a plugin that asks `iac.log` to
    /// read 1 GiB worth of bytes must NOT cause the host to
    /// allocate 1 GiB. The host caps at 64 KiB and tags the
    /// truncation. We can't easily assert on tracing output from a
    /// unit test, so we just call observe through a fixture that
    /// calls `iac.log` with a huge len and verify the call still
    /// completes (didn't OOM, didn't trap on host side).
    fn huge_log_fixture_wat() -> &'static str {
        r#"
(module
  (import "iac" "log" (func $log (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "test.kind")
  (data (i32.const 64) "{\"present\":false}")
  (global $next (mut i32) (i32.const 4096))
  (func (export "iac_alloc") (param i32) (result i32)
    (local $ret i32)
    (local.set $ret (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get 0)))
    (local.get $ret))
  (func (export "iac_dealloc") (param i32 i32) nop)
  (func (export "iac_kind") (result i64)
    (i64.or (i64.shl (i64.const 16) (i64.const 32)) (i64.const 9)))
  ;; Plugin asks the host to read 1 GiB starting at offset 0,
  ;; which is way past the legitimate data. The host MUST cap
  ;; before allocating, otherwise this test crashes the runner.
  (func (export "iac_observe") (param i32 i32) (result i64)
    (call $log (i32.const 0) (i32.const 1073741824))
    (i64.or (i64.shl (i64.const 64) (i64.const 32)) (i64.const 17)))
  (func (export "iac_apply") (param i32 i32) (result i64)
    (i64.or (i64.shl (i64.const 64) (i64.const 32)) (i64.const 17)))
)
"#
    }

    /// Phase 7dh.4: a `module_sha256` pin must reject mismatched
    /// bytes before compilation. This is the core integrity gate
    /// against an attacker who can swap the binary on disk.
    #[test]
    fn module_sha256_mismatch_rejected() {
        let bytes = wat::parse_str(fixture_wat()).unwrap();
        let spec = WasmProviderSpec {
            kind: "test.kind".into(),
            module: "/dev/null".into(),
            max_memory_bytes: 16 * 1024 * 1024,
            fuel_per_call: 10_000_000,
            runtime: WasmRuntimeKind::Core,
            wasi: super::super::spec::WasiConfig::default(),
            // 64 zeros — won't match the actual hash of `bytes`.
            module_sha256: Some(
                "0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
            ),
        };
        match WasmRuntime::from_bytes(spec, &bytes) {
            Ok(_) => panic!("expected pin error, got Ok"),
            Err(e) => {
                let msg = format!("{e:?}");
                assert!(msg.contains("hash mismatch"), "got {msg}");
            }
        }
    }

    #[test]
    fn module_sha256_match_succeeds() {
        use sha2::{Digest, Sha256};
        let bytes = wat::parse_str(fixture_wat()).unwrap();
        let actual = hex::encode(Sha256::digest(&bytes));
        let spec = WasmProviderSpec {
            kind: "test.kind".into(),
            module: "/dev/null".into(),
            max_memory_bytes: 16 * 1024 * 1024,
            fuel_per_call: 10_000_000,
            runtime: WasmRuntimeKind::Core,
            wasi: super::super::spec::WasiConfig::default(),
            module_sha256: Some(actual),
        };
        let rt = WasmRuntime::from_bytes(spec, &bytes).unwrap();
        rt.validate_kind().unwrap();
    }

    #[test]
    fn iac_log_cap_prevents_huge_alloc() {
        let bytes = wat::parse_str(huge_log_fixture_wat()).unwrap();
        let spec = WasmProviderSpec {
            kind: "test.kind".into(),
            module: "/dev/null".into(),
            max_memory_bytes: 16 * 1024 * 1024,
            fuel_per_call: 100_000_000,
            runtime: WasmRuntimeKind::Core,
            wasi: super::super::spec::WasiConfig::default(),
            module_sha256: None,
        };
        let rt = WasmRuntime::from_bytes(spec, &bytes).unwrap();
        // Should complete without OOMing — the host capped the
        // 1 GiB request at 64 KiB before allocating.
        let resp = rt.call("observe", b"{}").unwrap();
        assert!(resp.contains("present"));
    }

    #[test]
    fn fuel_traps_runaway_loops() {
        let bytes = wat::parse_str(infinite_loop_wat()).unwrap();
        let spec = WasmProviderSpec {
            kind: "test.kind".into(),
            module: "/dev/null".into(),
            max_memory_bytes: 16 * 1024 * 1024,
            fuel_per_call: 100_000,
            runtime: WasmRuntimeKind::Core,
            wasi: super::super::spec::WasiConfig::default(),
            module_sha256: None,
        };
        let rt = WasmRuntime::from_bytes(spec, &bytes).unwrap();
        let err = rt.call("observe", b"{}").unwrap_err();
        let msg = format!("{err:?}");
        // Wasmtime surfaces fuel exhaustion as a trap; the exact
        // error wording varies across releases (some emit "all fuel
        // consumed", some just "wasm backtrace"). All of those mean
        // "guest aborted before returning" — accept any of them.
        assert!(
            msg.contains("fuel")
                || msg.contains("trap")
                || msg.contains("wasm backtrace")
                || msg.contains("exhausted"),
            "expected fuel/trap error, got: {msg}"
        );
    }
}
