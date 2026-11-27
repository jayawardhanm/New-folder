//! Virtualized Xbox drive (`G:\`, `D:\`, `T:\`) -> PC game directory file I/O shims.

use std::ffi::{CString, c_void};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use scarlett_pe::ImportSymbol;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

static GAME_ROOT: OnceLock<PathBuf> = OnceLock::new();
static EXE_PATH: OnceLock<PathBuf> = OnceLock::new();
static EXE_BASE: OnceLock<usize> = OnceLock::new();
static CMD_LINE_A: OnceLock<CString> = OnceLock::new();
static ARGC: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(1);
static mut ARGV_PTR: *mut *mut u8 = std::ptr::null_mut();

pub fn init_paths(exe: &Path, base: usize) {
    let _ = EXE_PATH.set(exe.to_path_buf());
    let _ = EXE_BASE.set(base);
    let cmd = CString::new(format!("\"{}\"", exe.display())).unwrap_or_else(|_| CString::new("game.exe").unwrap());
    let arg0 = Box::leak(Box::new(cmd.clone())).as_ptr().cast_mut().cast::<u8>();
    let argv_vec = Box::leak(vec![arg0, std::ptr::null_mut()].into_boxed_slice());
    // SAFETY: initialized once before title execution starts.
    unsafe { ARGV_PTR = argv_vec.as_mut_ptr() };
    ARGC.store(1, std::sync::atomic::Ordering::Relaxed);
    let _ = CMD_LINE_A.set(cmd);
    if let Some(p) = exe.parent() {
        let _ = GAME_ROOT.set(p.to_path_buf());
    }
}

fn translate_wide(raw: *const u16) -> Option<Vec<u16>> {
    if raw.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: null-terminated UTF-16 string from caller.
    while unsafe { *raw.add(len) } != 0 && len < 4096 {
        len += 1;
    }
    // SAFETY: `raw..raw+len` is valid UTF-16.
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, len) });
    let mapped = translate_str(&s)?;
    let mut out: Vec<u16> = mapped.encode_utf16().collect();
    out.push(0);
    Some(out)
}

fn translate_str(s: &str) -> Option<String> {
    let root = GAME_ROOT.get()?;
    let norm = s.replace('/', "\\");
    let stripped = if let Some(rest) = norm.strip_prefix("\\\\?\\") {
        rest
    } else {
        &norm
    };
    let rest = if stripped.len() >= 2 && stripped.as_bytes()[1] == b':' {
        let drive = stripped.as_bytes()[0].to_ascii_uppercase();
        if matches!(drive, b'G' | b'D' | b'T') {
            stripped[2..].trim_start_matches('\\')
        } else {
            return None;
        }
    } else {
        return None;
    };
    Some(root.join(rest).to_string_lossy().into_owned())
}

fn host_proc(dll: &str, name: &str) -> Option<usize> {
    let c_dll = CString::new(dll).ok()?;
    let c_sym = CString::new(name).ok()?;
    // SAFETY: null-terminated ASCII strings.
    let h = unsafe { LoadLibraryA(c_dll.as_ptr().cast()) };
    if h.is_null() {
        return None;
    }
    // SAFETY: valid module handle and symbol name.
    unsafe { GetProcAddress(h, c_sym.as_ptr().cast()) }.map(|p| p as usize)
}

unsafe extern "system" fn hle_get_module_file_name_w(
    hmod: *mut c_void,
    buf: *mut u16,
    size: u32,
) -> u32 {
    if (hmod.is_null() || EXE_BASE.get().is_some_and(|&b| b == hmod as usize))
        && let Some(exe) = EXE_PATH.get()
        && !buf.is_null()
        && size > 0
    {
        let mut wide: Vec<u16> = exe.to_string_lossy().encode_utf16().collect();
        wide.push(0);
        let copy_len = wide.len().min(size as usize);
        // SAFETY: `buf` has capacity `size` UTF-16 code units.
        unsafe { std::ptr::copy_nonoverlapping(wide.as_ptr(), buf, copy_len) };
        if copy_len == size as usize {
            unsafe { *buf.add(copy_len - 1) = 0 };
        }
        return (copy_len - 1) as u32;
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut u16, u32) -> u32;
    let Some(p) = host_proc("kernel32.dll", "GetModuleFileNameW") else {
        return 0;
    };
    // SAFETY: exact Win32 signature.
    let f: FnTy = unsafe { std::mem::transmute(p) };
    unsafe { f(hmod, buf, size) }
}

unsafe extern "system" fn hle_create_file_w(
    name: *const u16,
    access: u32,
    share: u32,
    sec: *const c_void,
    disp: u32,
    flags: u32,
    tmpl: *mut c_void,
) -> *mut c_void {
    type FnTy = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *const c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void;
    let p = host_proc("kernel32.dll", "CreateFileW").unwrap();
    // SAFETY: exact Win32 signature.
    let f: FnTy = unsafe { std::mem::transmute(p) };
    if let Some(mapped) = translate_wide(name) {
        return unsafe { f(mapped.as_ptr(), access, share, sec, disp, flags, tmpl) };
    }
    unsafe { f(name, access, share, sec, disp, flags, tmpl) }
}

unsafe extern "system" fn hle_get_file_attributes_w(name: *const u16) -> u32 {
    type FnTy = unsafe extern "system" fn(*const u16) -> u32;
    let p = host_proc("kernel32.dll", "GetFileAttributesW").unwrap();
    // SAFETY: exact Win32 signature.
    let f: FnTy = unsafe { std::mem::transmute(p) };
    if let Some(mapped) = translate_wide(name) {
        return unsafe { f(mapped.as_ptr()) };
    }
    unsafe { f(name) }
}

unsafe extern "system" fn hle_get_file_attributes_ex_w(
    name: *const u16,
    level: u32,
    info: *mut c_void,
) -> i32 {
    type FnTy = unsafe extern "system" fn(*const u16, u32, *mut c_void) -> i32;
    let p = host_proc("kernel32.dll", "GetFileAttributesExW").unwrap();
    // SAFETY: exact Win32 signature.
    let f: FnTy = unsafe { std::mem::transmute(p) };
    if let Some(mapped) = translate_wide(name) {
        return unsafe { f(mapped.as_ptr(), level, info) };
    }
    unsafe { f(name, level, info) }
}

unsafe extern "system" fn hle_find_first_file_ex_w(
    name: *const u16,
    info_level: u32,
    data: *mut c_void,
    search_op: u32,
    filter: *mut c_void,
    flags: u32,
) -> *mut c_void {
    type FnTy =
        unsafe extern "system" fn(*const u16, u32, *mut c_void, u32, *mut c_void, u32) -> *mut c_void;
    let p = host_proc("kernel32.dll", "FindFirstFileExW").unwrap();
    // SAFETY: exact Win32 signature.
    let f: FnTy = unsafe { std::mem::transmute(p) };
    if let Some(mapped) = translate_wide(name) {
        return unsafe { f(mapped.as_ptr(), info_level, data, search_op, filter, flags) };
    }
    unsafe { f(name, info_level, data, search_op, filter, flags) }
}

unsafe extern "system" fn hle_get_module_file_name_a(
    hmod: *mut c_void,
    buf: *mut u8,
    size: u32,
) -> u32 {
    if (hmod.is_null() || EXE_BASE.get().is_some_and(|&b| b == hmod as usize))
        && let Some(exe) = EXE_PATH.get()
        && !buf.is_null()
        && size > 0
    {
        let s = exe.to_string_lossy();
        let bytes = s.as_bytes();
        let copy_len = bytes.len().min((size - 1) as usize);
        // SAFETY: `buf` has capacity `size`.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, copy_len);
            *buf.add(copy_len) = 0;
        }
        return copy_len as u32;
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, *mut u8, u32) -> u32;
    let Some(p) = host_proc("kernel32.dll", "GetModuleFileNameA") else {
        return 0;
    };
    // SAFETY: exact Win32 signature.
    let f: FnTy = unsafe { std::mem::transmute(p) };
    unsafe { f(hmod, buf, size) }
}

unsafe extern "system" fn hle_create_file_a(
    name: *const u8,
    access: u32,
    share: u32,
    sec: *const c_void,
    disp: u32,
    flags: u32,
    tmpl: *mut c_void,
) -> *mut c_void {
    if !name.is_null() {
        let mut len = 0usize;
        // SAFETY: null-terminated ASCII path.
        while unsafe { *name.add(len) } != 0 && len < 4096 {
            len += 1;
        }
        let s = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(name, len) });
        if let Some(mapped) = translate_str(&s)
            && let Ok(c) = CString::new(mapped)
        {
            type FnTy = unsafe extern "system" fn(
                *const u8,
                u32,
                u32,
                *const c_void,
                u32,
                u32,
                *mut c_void,
            ) -> *mut c_void;
            let p = host_proc("kernel32.dll", "CreateFileA").unwrap();
            let f: FnTy = unsafe { std::mem::transmute(p) };
            return unsafe { f(c.as_ptr().cast(), access, share, sec, disp, flags, tmpl) };
        }
    }
    type FnTy = unsafe extern "system" fn(
        *const u8,
        u32,
        u32,
        *const c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void;
    let p = host_proc("kernel32.dll", "CreateFileA").unwrap();
    let f: FnTy = unsafe { std::mem::transmute(p) };
    unsafe { f(name, access, share, sec, disp, flags, tmpl) }
}

unsafe extern "system" fn hle_get_proc_address(hmod: *mut c_void, name: *const u8) -> usize {
    if hmod as usize == crate::xgameruntime::XGAMERUNTIME_HANDLE && !name.is_null() && (name as usize) > 0xFFFF {
        let mut len = 0usize;
        while unsafe { *name.add(len) } != 0 && len < 256 {
            len += 1;
        }
        let s = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(name, len) });
        return crate::xgameruntime::get_proc_address(&s);
    }
    type FnTy = unsafe extern "system" fn(*mut c_void, *const u8) -> usize;
    let p = host_proc("kernel32.dll", "GetProcAddress").unwrap();
    let f: FnTy = unsafe { std::mem::transmute(p) };
    unsafe { f(hmod, name) }
}

unsafe extern "C" fn hle_p_argc() -> *mut i32 {
    (&raw const ARGC).cast_mut().cast()
}

unsafe extern "C" fn hle_p_argv() -> *mut *mut *mut u8 {
    &raw mut ARGV_PTR
}

unsafe extern "system" fn hle_load_library_w(name: *const u16) -> *mut c_void {
    if !name.is_null() {
        let mut len = 0usize;
        while unsafe { *name.add(len) } != 0 && len < 512 {
            len += 1;
        }
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(name, len) });
        eprintln!("[HLE] LoadLibraryW: {s}");
    }
    type FnTy = unsafe extern "system" fn(*const u16) -> *mut c_void;
    let p = host_proc("kernel32.dll", "LoadLibraryW").unwrap();
    let f: FnTy = unsafe { std::mem::transmute(p) };
    unsafe { f(name) }
}

unsafe extern "system" fn hle_load_library_ex_w(name: *const u16, hfile: *mut c_void, flags: u32) -> *mut c_void {
    if !name.is_null() {
        let mut len = 0usize;
        while unsafe { *name.add(len) } != 0 && len < 512 {
            len += 1;
        }
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(name, len) });
        eprintln!("[HLE] LoadLibraryExW: {s} flags={flags:#x}");
    }
    type FnTy = unsafe extern "system" fn(*const u16, *mut c_void, u32) -> *mut c_void;
    let p = host_proc("kernel32.dll", "LoadLibraryExW").unwrap();
    let f: FnTy = unsafe { std::mem::transmute(p) };
    unsafe { f(name, hfile, flags) }
}

unsafe extern "system" fn hle_load_library_ex_a(name: *const u8, hfile: *mut c_void, flags: u32) -> *mut c_void {
    if !name.is_null() {
        let mut len = 0usize;
        while unsafe { *name.add(len) } != 0 && len < 512 {
            len += 1;
        }
        let s = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(name, len) });
        eprintln!("[HLE] LoadLibraryExA: {s} flags={flags:#x}");
    }
    type FnTy = unsafe extern "system" fn(*const u8, *mut c_void, u32) -> *mut c_void;
    let p = host_proc("kernel32.dll", "LoadLibraryExA").unwrap();
    let f: FnTy = unsafe { std::mem::transmute(p) };
    unsafe { f(name, hfile, flags) }
}

unsafe extern "system" fn hle_get_command_line_a() -> *const u8 {
    if let Some(c) = CMD_LINE_A.get() {
        return c.as_ptr().cast();
    }
    c"game_scarlett_master.exe".as_ptr().cast()
}

unsafe extern "system" fn hle_get_module_handle_a(name: *const u8) -> *mut c_void {
    if name.is_null()
        && let Some(&base) = EXE_BASE.get()
    {
        return base as *mut c_void;
    }
    type FnTy = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let p = host_proc("kernel32.dll", "GetModuleHandleA").unwrap();
    let f: FnTy = unsafe { std::mem::transmute(p) };
    unsafe { f(name) }
}

unsafe extern "system" fn hle_get_module_handle_w(name: *const u16) -> *mut c_void {
    if name.is_null()
        && let Some(&base) = EXE_BASE.get()
    {
        return base as *mut c_void;
    }
    type FnTy = unsafe extern "system" fn(*const u16) -> *mut c_void;
    let p = host_proc("kernel32.dll", "GetModuleHandleW").unwrap();
    let f: FnTy = unsafe { std::mem::transmute(p) };
    unsafe { f(name) }
}

unsafe extern "system" fn hle_find_first_file_w(name: *const u16, data: *mut c_void) -> *mut c_void {
    type FnTy = unsafe extern "system" fn(*const u16, *mut c_void) -> *mut c_void;
    let p = host_proc("kernel32.dll", "FindFirstFileW").unwrap();
    let f: FnTy = unsafe { std::mem::transmute(p) };
    if let Some(mapped) = translate_wide(name) {
        return unsafe { f(mapped.as_ptr(), data) };
    }
    unsafe { f(name, data) }
}

unsafe extern "system" fn hle_get_disk_free_space_ex_w(
    dir: *const u16,
    avail: *mut u64,
    total: *mut u64,
    free: *mut u64,
) -> i32 {
    type FnTy = unsafe extern "system" fn(*const u16, *mut u64, *mut u64, *mut u64) -> i32;
    let p = host_proc("kernel32.dll", "GetDiskFreeSpaceExW").unwrap();
    let f: FnTy = unsafe { std::mem::transmute(p) };
    if let Some(mapped) = translate_wide(dir) {
        return unsafe { f(mapped.as_ptr(), avail, total, free) };
    }
    unsafe { f(dir, avail, total, free) }
}

unsafe extern "system" fn hle_create_directory_w(name: *const u16, sec: *const c_void) -> i32 {
    type FnTy = unsafe extern "system" fn(*const u16, *const c_void) -> i32;
    let p = host_proc("kernel32.dll", "CreateDirectoryW").unwrap();
    let f: FnTy = unsafe { std::mem::transmute(p) };
    if let Some(mapped) = translate_wide(name) {
        return unsafe { f(mapped.as_ptr(), sec) };
    }
    unsafe { f(name, sec) }
}

unsafe extern "system" fn hle_get_file_attributes_a(name: *const u8) -> u32 {
    if !name.is_null() {
        let mut len = 0usize;
        while unsafe { *name.add(len) } != 0 && len < 4096 {
            len += 1;
        }
        let s = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(name, len) });
        if let Some(mapped) = translate_str(&s)
            && let Ok(c) = CString::new(mapped)
        {
            type FnTy = unsafe extern "system" fn(*const u8) -> u32;
            let p = host_proc("kernel32.dll", "GetFileAttributesA").unwrap();
            let f: FnTy = unsafe { std::mem::transmute(p) };
            return unsafe { f(c.as_ptr().cast()) };
        }
    }
    type FnTy = unsafe extern "system" fn(*const u8) -> u32;
    let p = host_proc("kernel32.dll", "GetFileAttributesA").unwrap();
    let f: FnTy = unsafe { std::mem::transmute(p) };
    unsafe { f(name) }
}

pub fn resolve(sym: &ImportSymbol<'_>) -> Option<usize> {
    let ImportSymbol::Name(n) = sym else {
        return None;
    };
    let addr = match *n {
        "__p___argc" => hle_p_argc as *const () as usize,
        "__p___argv" => hle_p_argv as *const () as usize,
        "LoadLibraryW" => hle_load_library_w as *const () as usize,
        "LoadLibraryExW" => hle_load_library_ex_w as *const () as usize,
        "LoadLibraryExA" => hle_load_library_ex_a as *const () as usize,
        "GetProcAddress" => hle_get_proc_address as *const () as usize,
        "GetCommandLineA" => hle_get_command_line_a as *const () as usize,
        "GetModuleHandleA" => hle_get_module_handle_a as *const () as usize,
        "GetModuleHandleW" => hle_get_module_handle_w as *const () as usize,
        "GetModuleFileNameA" => hle_get_module_file_name_a as *const () as usize,
        "GetModuleFileNameW" => hle_get_module_file_name_w as *const () as usize,
        "CreateFileA" => hle_create_file_a as *const () as usize,
        "CreateFileW" => hle_create_file_w as *const () as usize,
        "CreateDirectoryW" => hle_create_directory_w as *const () as usize,
        "GetFileAttributesA" => hle_get_file_attributes_a as *const () as usize,
        "GetFileAttributesW" => hle_get_file_attributes_w as *const () as usize,
        "GetFileAttributesExW" => hle_get_file_attributes_ex_w as *const () as usize,
        "FindFirstFileW" => hle_find_first_file_w as *const () as usize,
        "FindFirstFileExW" => hle_find_first_file_ex_w as *const () as usize,
        "GetDiskFreeSpaceExW" => hle_get_disk_free_space_ex_w as *const () as usize,
        _ => return None,
    };
    Some(addr)
}
