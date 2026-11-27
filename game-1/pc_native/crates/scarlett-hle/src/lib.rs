//! High-level emulation (HLE) and host Win32/GDK binder for Scarlett titles.

pub mod audio_input;
pub mod dstorage;
pub mod file_io;
pub mod xgameruntime;
pub mod xmem;

use std::collections::HashMap;
use std::ffi::{CString, c_void};
use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use scarlett_pe::{ImportSymbol, MappedImage};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RtlLookupFunctionEntry, RtlVirtualUnwind,
    EXCEPTION_POINTERS, UNW_FLAG_NHANDLER,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Threading::{
    CreateThread as win_create_thread, GetCurrentProcess, TerminateProcess,
};

pub struct Runtime {
    pub exe: MappedImage,
    pub dlls: Vec<MappedImage>,
}

/// Loads `exe` and companion title DLLs from `game_dir`, binding imports against
/// title DLLs, HLE shims, and host Windows libraries.
pub fn load_title(exe_path: &Path) -> Result<Runtime> {
    let game_dir = exe_path.parent().unwrap_or_else(|| Path::new("."));
    let companion_names = [
        "XboxBvhBuilder.dll",
        "amd_fidelityfx_loader_xbox.dll",
        "libHttpClient.GDK.dll",
        "Bink2Scarlett.dll",
    ];

    let mut dlls = Vec::new();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    for (idx, name) in companion_names.iter().enumerate() {
        let p = game_dir.join(name);
        if p.exists() {
            let img = MappedImage::load_file(&p)?;
            by_name.insert(name.to_ascii_lowercase(), idx);
            dlls.push(img);
        }
    }

    let exe = MappedImage::load_file(exe_path)?;
    xmem::set_title_allocation_hooks(
        exe.export(&ImportSymbol::Name("__XMemAllocationHooks__")),
    );
    file_io::init_paths(exe_path, exe.base);

    let resolve_for = |dll: &str, sym: &ImportSymbol<'_>, title_dlls: &[MappedImage]| -> Option<usize> {
        let lower = dll.to_ascii_lowercase();
        if let Some(&i) = by_name.get(&lower) {
            return title_dlls[i].export(sym);
        }
        if let ImportSymbol::Name(n) = sym {
            let resolved = match lower.as_str() {
                "xmem.dll" => xmem::resolve(n),
                "xcrdapi.dll" => dstorage::resolve(n),
                "d3d12_xs.dll" => scarlett_gpu::xs_entry::resolve_d3d12_xs(n),
                "xg_xs.dll" => scarlett_gpu::xs_entry::resolve_xg_xs(n),
                _ => None,
            };
            if resolved.is_some() {
                return resolved;
            }
        }
        if let Some(addr) = audio_input::resolve(&lower, sym) {
            return Some(addr);
        }
        if let Some(addr) = file_io::resolve(sym) {
            return Some(addr);
        }
        if let ImportSymbol::Name("CreateThread") = sym {
            return Some(hle_create_thread as *const () as usize);
        }
        if let ImportSymbol::Name("_beginthreadex") = sym {
            return Some(hle_beginthreadex as *const () as usize);
        }
        if let ImportSymbol::Name("VirtualFree") = sym {
            return Some(xmem::hle_virtual_free as *const () as usize);
        }
        if let ImportSymbol::Name("ExitProcess") = sym {
            return Some(hle_exit_process as *const () as usize);
        }
        // Try host Windows library for standard Win32 / CRT / API-sets.
        if lower.starts_with("api-ms-win-")
            || lower.starts_with("ext-ms-win-")
            || matches!(
                lower.as_str(),
                "kernel32.dll"
                    | "advapi32.dll"
                    | "crypt32.dll"
                    | "ws2_32.dll"
                    | "winhttp.dll"
                    | "bcrypt.dll"
                    | "mfplat.dll"
                    | "mfreadwrite.dll"
                    | "vcruntime140.dll"
                    | "vcruntime140_1.dll"
                    | "msvcp140.dll"
            )
        {
            let c_dll = CString::new(dll).ok()?;
            // SAFETY: null-terminated ASCII DLL name.
            let hmod = unsafe { LoadLibraryA(c_dll.as_ptr().cast()) };
            if !hmod.is_null() {
                let proc = match sym {
                    ImportSymbol::Name(n) => {
                        let c_sym = CString::new(*n).ok()?;
                        // SAFETY: valid module handle and null-terminated symbol name.
                        unsafe { GetProcAddress(hmod, c_sym.as_ptr().cast()) }
                    }
                    ImportSymbol::Ordinal(o) => {
                        // SAFETY: ordinal lookup via `MAKEINTRESOURCEA`.
                        unsafe { GetProcAddress(hmod, (*o as usize) as *const u8) }
                    }
                };
                if let Some(p) = proc {
                    return Some(p as usize);
                }
            }
        }
        None
    };

    for dll in &dlls {
        let rep = dll.bind_imports(|d, s| resolve_for(d, s, &dlls))?;
        tracing::info!(module = %dll.name, bound = rep.bound_total, missing = rep.missing.len(), "bound companion DLL");
        for (m_dll, m_sym) in &rep.missing {
            tracing::warn!(module = %dll.name, dll = %m_dll, sym = %m_sym, "missing import");
        }
    }
    let rep = exe.bind_imports(|d, s| resolve_for(d, s, &dlls))?;
    tracing::info!(module = %exe.name, bound = rep.bound_total, missing = rep.missing.len(), "bound executable");
    for (m_dll, m_sym) in &rep.missing {
        tracing::warn!(module = %exe.name, dll = %m_dll, sym = %m_sym, "missing import");
    }

    // Pre-load system DLLs that the title dynamically loads later so `ntdll`
    // initializes their TLS/Ldr state before we bind the title's `gs:[0x58]`.
    for preload in ["dbghelp.dll", "rpcrt4.dll"] {
        if let Ok(c) = CString::new(preload) {
            // SAFETY: null-terminated ASCII DLL name.
            unsafe { LoadLibraryA(c.as_ptr().cast()) };
        }
    }

    Ok(Runtime { exe, dlls })
}

static EXE_TLS: OnceLock<ExeTlsInfo> = OnceLock::new();

#[derive(Clone, Copy)]
struct ExeTlsInfo {
    tls_index: Option<u32>,
    tls_raw_start: usize,
    tls_raw_size: usize,
    tls_zero_fill: usize,
}

static TLS_BLOCKS: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

unsafe fn exe_tls_initialized_on_thread() -> bool {
    let tls_array: *mut *mut u8;
    // SAFETY: reading `gs:[0x58]`.
    unsafe {
        std::arch::asm!("mov {}, gs:[0x58]", out(reg) tls_array, options(nostack, readonly));
    }
    if tls_array.is_null() {
        return false;
    }
    // SAFETY: slot 0 exists in `ntdll`'s `gs:[0x58]`.
    let cur = unsafe { *tls_array } as usize;
    TLS_BLOCKS
        .lock()
        .map(|g| g.contains(&cur))
        .unwrap_or(false)
}

unsafe fn init_exe_tls_current_thread() {
    let Some(info) = EXE_TLS.get() else {
        return;
    };
    let total = (info.tls_raw_size + info.tls_zero_fill).max(64);
    let block = vec![0u8; total].into_boxed_slice();
    let block_ptr = Box::into_raw(block).cast::<u8>();
    if info.tls_raw_size > 0 && info.tls_raw_start != 0 {
        // SAFETY: `tls_raw_start..+tls_raw_size` lies inside mapped `.tls` and `block_ptr` has `total` bytes.
        unsafe { std::ptr::copy_nonoverlapping(info.tls_raw_start as *const u8, block_ptr, info.tls_raw_size) };
    }
    let tls_array: *mut *mut u8;
    // SAFETY: reading `gs:[0x58]`.
    unsafe {
        std::arch::asm!("mov {}, gs:[0x58]", out(reg) tls_array, options(nostack, readonly));
    }
    if !tls_array.is_null() {
        // SAFETY: slot 0 exists in `ntdll`'s `gs:[0x58]`.
        unsafe { *tls_array = block_ptr };
    }
    if let Ok(mut g) = TLS_BLOCKS.lock() {
        g.push(block_ptr as usize);
    }
}

struct ThreadStart {
    entry: unsafe extern "system" fn(*mut c_void) -> u32,
    param: *mut c_void,
}
// SAFETY: `ThreadStart` forwards caller-provided Win32 `CreateThread` start routine and parameter.
unsafe impl Send for ThreadStart {}

unsafe extern "system" fn thread_trampoline(raw: *mut c_void) -> u32 {
    // SAFETY: boxed via `Box::into_raw` in `hle_create_thread`.
    let start = unsafe { Box::from_raw(raw.cast::<ThreadStart>()) };
    // SAFETY: initialize exe TLS block on this newly spawned title thread.
    unsafe { init_exe_tls_current_thread() };
    // SAFETY: invoke title's thread routine.
    unsafe { (start.entry)(start.param) }
}

unsafe extern "system" fn hle_create_thread(
    attrs: *const c_void,
    stack_size: usize,
    start: Option<unsafe extern "system" fn(*mut c_void) -> u32>,
    param: *mut c_void,
    flags: u32,
    tid: *mut u32,
) -> *mut c_void {
    let Some(entry) = start else {
        return std::ptr::null_mut();
    };
    let boxed = Box::into_raw(Box::new(ThreadStart { entry, param }));
    // SAFETY: delegates to Win32 `CreateThread` with our TLS-initializing trampoline.
    unsafe { win_create_thread(attrs.cast(), stack_size, Some(thread_trampoline), boxed.cast(), flags, tid) }
}

unsafe extern "system" fn hle_beginthreadex(
    attrs: *const c_void,
    stack_size: u32,
    start: Option<unsafe extern "system" fn(*mut c_void) -> u32>,
    param: *mut c_void,
    flags: u32,
    tid: *mut u32,
) -> *mut c_void {
    type BeginThreadExFn = unsafe extern "system" fn(
        *const c_void,
        u32,
        Option<unsafe extern "system" fn(*mut c_void) -> u32>,
        *mut c_void,
        u32,
        *mut u32,
    ) -> *mut c_void;
    let Some(entry) = start else {
        return std::ptr::null_mut();
    };
    let Ok(c_dll) = CString::new("ucrtbase.dll") else {
        return std::ptr::null_mut();
    };
    let Ok(c_sym) = CString::new("_beginthreadex") else {
        return std::ptr::null_mut();
    };
    // SAFETY: lookup `_beginthreadex` in host `ucrtbase.dll`.
    let h = unsafe { LoadLibraryA(c_dll.as_ptr().cast()) };
    if h.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: valid module handle and symbol name.
    let Some(p) = (unsafe { GetProcAddress(h, c_sym.as_ptr().cast()) }) else {
        return std::ptr::null_mut();
    };
    let real: BeginThreadExFn = unsafe { std::mem::transmute(p) };
    let boxed = Box::into_raw(Box::new(ThreadStart { entry, param }));
    // SAFETY: forwarding to host `_beginthreadex` with our TLS-initializing trampoline.
    unsafe { real(attrs, stack_size, Some(thread_trampoline), boxed.cast(), flags, tid) }
}

unsafe extern "system" fn vectored_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    if info.is_null() {
        return 0;
    }
    // SAFETY: `info`, `ExceptionRecord`, and `ContextRecord` are valid in VEH callback.
    unsafe {
        let rec = &*(*info).ExceptionRecord;
        let ctx = &mut *(*info).ContextRecord;
        // Ignore normal MSVC C++ EH (0xE06D7363), thread-naming (0x406D1388), and OutputDebugString (0x40010006/0x4001000A).
        let code = rec.ExceptionCode as u32;
        // The Xbox build asserts when its reserved GPU memory slack is absent.
        // This assertion is expected for the PC allocator and the prior run
        // confirmed execution can continue immediately after its `int 3`.
        if code == 0x8000_0003 && ctx.Rip == 0x14247_AF2D {
            eprintln!("[VEH] continuing past Xbox memory-slack assert at {:#x}", ctx.Rip);
            ctx.Rip += 1;
            return -1; // EXCEPTION_CONTINUE_EXECUTION
        }
        if code == 0xE06D_7363 {
            eprintln!(
                "[VEH] C++ exception params={:#x?}",
                &rec.ExceptionInformation[..(rec.NumberParameters as usize).min(4)]
            );
            if rec.NumberParameters >= 2 && rec.ExceptionInformation[1] > 0x10000 {
                let object = rec.ExceptionInformation[1] as *const u8;
                let bytes = std::slice::from_raw_parts(object, 64);
                eprintln!("[VEH] C++ exception object={bytes:#x?}");
                eprintln!("[VEH] C++ exception text={}", String::from_utf8_lossy(bytes));
            }
            if rec.NumberParameters >= 3 {
                let throw_info = rec.ExceptionInformation[2] as usize;
                let fields = throw_info as *const i32;
                eprintln!("[VEH] C++ throw info={:#x?}", std::slice::from_raw_parts(fields, 4));
            }
            let mut unwind = *ctx;
            let mut bt = Vec::new();
            for _ in 0..16 {
                let pc = unwind.Rip;
                if pc == 0 || bt.contains(&pc) {
                    break;
                }
                bt.push(pc);
                let mut image_base = 0u64;
                let entry = RtlLookupFunctionEntry(pc, &mut image_base, std::ptr::null_mut());
                if entry.is_null() {
                    if unwind.Rsp == 0 {
                        break;
                    }
                    unwind.Rip = *(unwind.Rsp as *const u64);
                    unwind.Rsp += 8;
                } else {
                    let mut handler_data = std::ptr::null_mut();
                    let mut establisher = 0u64;
                    RtlVirtualUnwind(
                        UNW_FLAG_NHANDLER,
                        image_base,
                        pc,
                        entry,
                        &mut unwind,
                        &mut handler_data,
                        &mut establisher,
                        std::ptr::null_mut(),
                    );
                }
            }
            eprintln!("[VEH] C++ throw rip={:#x} unwind={bt:#x?}", ctx.Rip);
            return 0;
        }
        if matches!(code, 0x406D_1388 | 0x4001_0006 | 0x4001_000A) {
            return 0;
        }
        let fault_addr = if rec.NumberParameters >= 2 {
            rec.ExceptionInformation[1]
        } else {
            0
        };
        if (rec.ExceptionCode as u32) == 0xC000_0005 && fault_addr < 0x2000 && !exe_tls_initialized_on_thread() {
            init_exe_tls_current_thread();
            return -1; // EXCEPTION_CONTINUE_EXECUTION
        }
        let rdx_str = if ctx.Rdx > 0x10000 {
            let s = std::slice::from_raw_parts(ctx.Rdx as *const u8, 64);
            let nul = s.iter().position(|&b| b == 0).unwrap_or(s.len());
            String::from_utf8_lossy(&s[..nul]).into_owned()
        } else {
            String::new()
        };
        let mut bt = Vec::new();
        if ctx.Rsp != 0 {
            let p = ctx.Rsp as *const u64;
            for i in 0..48usize {
                let v = *p.add(i);
                if (0x1_4000_1000..0x1_4600_0000).contains(&v) && bt.len() < 8 {
                    bt.push(format!("{v:#x}"));
                }
            }
        }
        let mut raw_stack = [0u64; 8];
        if ctx.Rsp != 0 {
            let p = ctx.Rsp as *const u64;
            for i in 0..8 {
                raw_stack[i] = *p.add(i);
            }
        }
        // Use eprintln! / raw stderr write without tracing's thread-local subscriber.
        let mut stack_window = [0u64; 20];
        if ctx.Rsp != 0 {
            let p = ctx.Rsp as *const u64;
            for (i, slot) in stack_window.iter_mut().enumerate() {
                *slot = *p.add(i);
            }
        }
        eprintln!(
            "[VEH] code={:#x} rip={:#x} rsp={:#x} rbp={:#x} rax={:#x} rcx={:#x} rdx={:#x} ({:?}) fault={:#x} bt={:?} stack={:#x?}",
            rec.ExceptionCode,
            ctx.Rip,
            ctx.Rsp,
            ctx.Rbp,
            ctx.Rax,
            ctx.Rcx,
            ctx.Rdx,
            rdx_str,
            fault_addr,
            bt,
            stack_window,
        );
        TerminateProcess(GetCurrentProcess(), 1);
        0
    }
}

unsafe extern "system" fn hle_exit_process(code: u32) -> ! {
    eprintln!("[HLE] ExitProcess(code={code:#x})");
    unsafe { windows_sys::Win32::System::Threading::ExitProcess(code) }
}

/// Calls `DllMain(DLL_PROCESS_ATTACH)` for companion DLLs, runs exe TLS callbacks,
/// and invokes the executable entrypoint.
pub unsafe fn execute_title(rt: &Runtime) -> i32 {
    let _ = EXE_TLS.set(ExeTlsInfo {
        tls_index: rt.exe.tls_index,
        tls_raw_start: rt.exe.tls_raw_start,
        tls_raw_size: rt.exe.tls_raw_size,
        tls_zero_fill: rt.exe.tls_zero_fill,
    });
    // SAFETY: registering first-chance vectored exception handler for diagnostics.
    unsafe { AddVectoredExceptionHandler(1, Some(vectored_handler)) };

    type DllMain = unsafe extern "system" fn(usize, u32, usize) -> i32;
    type TlsCb = unsafe extern "system" fn(usize, u32, usize);
    type ExeEntry = unsafe extern "system" fn() -> i32;

    const DLL_PROCESS_ATTACH: u32 = 1;

    for dll in &rt.dlls {
        // SAFETY: initialize TLS block for companion DLL on main thread.
        unsafe { dll.init_thread_tls(false) };
        for &cb in &dll.tls_callbacks {
            // SAFETY: valid TLS callback in mapped companion DLL.
            let f: TlsCb = unsafe { std::mem::transmute(cb) };
            unsafe { f(dll.base, DLL_PROCESS_ATTACH, 0) };
        }
        if dll.entry_point != 0 {
            tracing::info!(module = %dll.name, "calling DllMain");
            // SAFETY: valid `DllMain` entrypoint in mapped companion DLL.
            let f: DllMain = unsafe { std::mem::transmute(dll.entry_point) };
            unsafe { f(dll.base, DLL_PROCESS_ATTACH, 0) };
        }
    }

    tracing::info!(callbacks = rt.exe.tls_callbacks.len(), "running exe TLS callbacks & entering exe");
    // SAFETY: initialize TLS block for main executable (including slot 0 for LTCG TLS fast-path).
    unsafe { rt.exe.init_thread_tls(true) };
    for &cb in &rt.exe.tls_callbacks {
        // SAFETY: valid TLS callback in mapped executable.
        let f: TlsCb = unsafe { std::mem::transmute(cb) };
        unsafe { f(rt.exe.base, DLL_PROCESS_ATTACH, 0) };
    }

    tracing::info!("entering exe entrypoint");
    // SAFETY: mapped executable entrypoint with all IAT imports bound.
    let ep: ExeEntry = unsafe { std::mem::transmute(rt.exe.entry_point) };
    unsafe { ep() }
}
