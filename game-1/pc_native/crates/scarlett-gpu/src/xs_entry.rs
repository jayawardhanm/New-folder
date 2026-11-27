//! Entrypoints for `d3d12_xs.dll` and `xg_xs.dll` backed by the PC-native D3D12 device.

use std::ffi::{CString, c_void};

use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

#[unsafe(no_mangle)]
pub unsafe extern "system" fn d3d12_configure_virtual_memory_x(_params: *const c_void) -> i32 {
    0 // S_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn d3d12_serialize_versioned_root_signature(
    desc: *const c_void,
    blob: *mut *mut c_void,
    error_blob: *mut *mut c_void,
) -> i32 {
    type FnTy = unsafe extern "system" fn(*const c_void, *mut *mut c_void, *mut *mut c_void) -> i32;
    let Ok(c_dll) = CString::new("d3d12.dll") else {
        return -2147467259;
    };
    let Ok(c_sym) = CString::new("D3D12SerializeVersionedRootSignature") else {
        return -2147467259;
    };
    // SAFETY: forwarding directly to host `d3d12.dll`.
    let hmod = unsafe { LoadLibraryA(c_dll.as_ptr().cast()) };
    if hmod.is_null() {
        return -2147467259;
    }
    // SAFETY: symbol lookup on host `d3d12.dll`.
    let Some(proc) = (unsafe { GetProcAddress(hmod, c_sym.as_ptr().cast()) }) else {
        return -2147467259;
    };
    // SAFETY: exact matching signature.
    let f: FnTy = unsafe { std::mem::transmute(proc) };
    // SAFETY: forwarding caller args.
    if desc.is_null() || blob.is_null() {
        return -2147467261;
    }
    let version = unsafe { *(desc.cast::<u32>()) };
    // The Xbox ABI assigns different bits to the two directly indexed heaps.
    // D3D12_ROOT_SIGNATURE_DESC1::Flags is at +0x28 for version 1.1.
    let mut translated_desc = [0u8; 56];
    unsafe { std::ptr::copy_nonoverlapping(desc.cast::<u8>(), translated_desc.as_mut_ptr(), translated_desc.len()) };
    if version == 2 {
        let flags_ptr = unsafe { translated_desc.as_mut_ptr().add(40).cast::<u32>() };
        let xbox_flags = unsafe { *flags_ptr };
        let pc_flags = (xbox_flags & !0x0300_0000)
            | if xbox_flags & 0x0100_0000 != 0 { 0x400 } else { 0 }
            | if xbox_flags & 0x0200_0000 != 0 { 0x800 } else { 0 };
        unsafe { *flags_ptr = pc_flags };
        if pc_flags != xbox_flags {
            eprintln!("[GPU] translated Xbox root signature flags {xbox_flags:#x} -> {pc_flags:#x}");
        }
    }
    let mut local_error = std::ptr::null_mut();
    let error_out = if error_blob.is_null() {
        &mut local_error
    } else {
        error_blob
    };
    let hr = unsafe { f(translated_desc.as_ptr().cast(), blob, error_out) };
    eprintln!("[GPU] SerializeVersionedRootSignature version={version} desc={desc:p} hr={hr:#x}");
    if hr < 0 {
        let err = unsafe { *error_out };
        if !err.is_null() {
            unsafe {
                let vtbl = *(err.cast::<*const *const c_void>());
                let get_ptr: unsafe extern "system" fn(*mut c_void) -> *const u8 =
                    std::mem::transmute(*vtbl.add(3));
                let get_len: unsafe extern "system" fn(*mut c_void) -> usize =
                    std::mem::transmute(*vtbl.add(4));
                let ptr = get_ptr(err);
                let len = get_len(err).min(2048);
                let msg = String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len));
                eprintln!("[GPU] root signature serialization error: {msg}");
                let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(*vtbl.add(2));
                release(err);
            }
        }
    }
    hr
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn d3d12_xbox_create_device(
    _adapter: *mut c_void,
    _params: *const c_void,
    _riid: *const c_void,
    ppv: *mut *mut c_void,
) -> i32 {
    if ppv.is_null() {
        return -2147467261;
    }
    match crate::device_x::create_xbox_device_x() {
        Ok(dev) => {
            eprintln!("[GPU] D3D12XboxCreateDevice -> XboxDeviceX ({:p})", dev);
            // SAFETY: valid out pointer.
            unsafe { *ppv = dev.cast() };
            0
        }
        Err(e) => {
            eprintln!("[GPU] D3D12XboxCreateDevice failed: {e:#}");
            -2147467259
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xg_create_texture_computer(
    _desc: *const c_void,
    ppv: *mut *mut c_void,
) -> i32 {
    if ppv.is_null() {
        return -2147467261;
    }
    // SAFETY: valid out pointer.
    unsafe { *ppv = crate::xg::create_texture_computer().cast() };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xg_suggest_swizzle_mode(
    _base: u32,
    _flags: u32,
    _dim: u32,
    _format: u32,
) -> u32 {
    0 // XG_SWIZZLE_MODE_LINEAR
}

pub fn resolve_d3d12_xs(name: &str) -> Option<usize> {
    match name {
        "D3D12ConfigureVirtualMemoryX" => Some(d3d12_configure_virtual_memory_x as *const () as usize),
        "D3D12SerializeVersionedRootSignature" => {
            Some(d3d12_serialize_versioned_root_signature as *const () as usize)
        }
        "D3D12XboxCreateDevice" => Some(d3d12_xbox_create_device as *const () as usize),
        _ => None,
    }
}

pub fn resolve_xg_xs(name: &str) -> Option<usize> {
    match name {
        "XGCreateTextureComputer" => Some(xg_create_texture_computer as *const () as usize),
        "XGSuggestSwizzleMode" => Some(xg_suggest_swizzle_mode as *const () as usize),
        _ => None,
    }
}
