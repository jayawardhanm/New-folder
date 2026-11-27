//! `xgameruntime.dll` HLE pseudo-module (`InitializeApiImpl`, `QueryApiImpl`, etc.).

use std::ffi::c_void;

pub const XGAMERUNTIME_HANDLE: usize = 0x6000_0001;
const E_NOTIMPL_WIN32: i32 = 0x8007_0032_u32 as i32; // ERROR_NOT_SUPPORTED

unsafe extern "system" fn init_api_impl(_version: u32, _reserved: *const c_void) -> i32 {
    0 // S_OK
}

unsafe extern "system" fn uninit_api_impl() {}

unsafe extern "system" fn query_api_impl(
    _provider: *const c_void,
    _iid: *const c_void,
    out: *mut *mut c_void,
) -> i32 {
    if !out.is_null() {
        // SAFETY: valid out pointer.
        unsafe { *out = std::ptr::null_mut() };
    }
    E_NOTIMPL_WIN32
}

unsafe extern "system" fn xerror_report(_hr: i32, _msg: *const u8) -> i32 {
    1
}

pub fn get_proc_address(name: &str) -> usize {
    eprintln!("[HLE] xgameruntime GetProcAddress: {name}");
    match name {
        "InitializeApiImpl" => init_api_impl as *const () as usize,
        "UninitializeApiImpl" => uninit_api_impl as *const () as usize,
        "QueryApiImpl" => query_api_impl as *const () as usize,
        "XErrorReport" => xerror_report as *const () as usize,
        _ => init_api_impl as *const () as usize,
    }
}
