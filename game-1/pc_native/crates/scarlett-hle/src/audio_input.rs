//! Audio (`chad.dll`, `xapu.dll`, `AcpHal.dll`, `XAudio2_9.dll`) and `GameInput.dll` HLE shims.

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use scarlett_pe::ImportSymbol;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

#[repr(C)]
struct ComStub {
    vtable: *const *const c_void,
    ref_count: AtomicU32,
}

#[repr(transparent)]
struct SyncVtbl<const N: usize>([*const c_void; N]);
// SAFETY: function pointers in static COM vtables are immutable and thread-safe.
unsafe impl<const N: usize> Sync for SyncVtbl<N> {}

unsafe extern "system" fn com_qi(
    this: *mut ComStub,
    _riid: *const c_void,
    ppv: *mut *mut c_void,
) -> i32 {
    if !ppv.is_null() {
        // SAFETY: valid out pointer.
        unsafe { *ppv = this.cast() };
    }
    // SAFETY: `this` is valid `ComStub`.
    unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) };
    0
}

unsafe extern "system" fn com_addref(this: *mut ComStub) -> u32 {
    // SAFETY: `this` is valid `ComStub`.
    unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) + 1 }
}

unsafe extern "system" fn com_release(this: *mut ComStub) -> u32 {
    // SAFETY: `this` is valid `ComStub`.
    let prev = unsafe { (*this).ref_count.fetch_sub(1, Ordering::AcqRel) };
    if prev == 1 {
        // SAFETY: boxed via `Box::into_raw`.
        unsafe { drop(Box::from_raw(this)) };
    }
    prev.saturating_sub(1)
}

unsafe extern "system" fn stub_ok_u64() -> u64 {
    0
}

unsafe extern "system" fn game_input_get_reading(
    _this: *mut c_void,
    _kind: u32,
    _device: *mut c_void,
    reading: *mut *mut c_void,
) -> i32 {
    if !reading.is_null() {
        // SAFETY: valid out pointer.
        unsafe { *reading = ptr::null_mut() };
    }
    // GAMEINPUT_E_READING_NOT_FOUND
    0x838A_0001u32 as i32
}

static GAME_INPUT_VTBL: SyncVtbl<24> = SyncVtbl([
    com_qi as *const c_void,
    com_addref as *const c_void,
    com_release as *const c_void,
    stub_ok_u64 as *const c_void, // GetCurrentTimestamp
    game_input_get_reading as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
    stub_ok_u64 as *const c_void,
]);

#[unsafe(no_mangle)]
pub unsafe extern "system" fn game_input_create(ppv: *mut *mut c_void) -> i32 {
    if ppv.is_null() {
        return -2147467261; // E_POINTER
    }
    let obj = Box::into_raw(Box::new(ComStub {
        vtable: GAME_INPUT_VTBL.0.as_ptr(),
        ref_count: AtomicU32::new(1),
    }));
    // SAFETY: valid out pointer.
    unsafe { *ppv = obj.cast() };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xaudio2_create(ppv: *mut *mut c_void, _flags: u32, _proc: u32) -> i32 {
    // Reuse generic COM stub for early boot; audio device hook can replace later.
    unsafe { game_input_create(ppv) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn ret_ok() -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn apu_alloc(
    _heap: *mut c_void,
    size: u32,
    _align: u32,
) -> *mut c_void {
    // SAFETY: standard VirtualAlloc backing for APU heap allocations.
    unsafe { VirtualAlloc(ptr::null(), (size as usize).max(4096), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn apu_free(addr: *mut c_void) {
    if !addr.is_null() {
        // SAFETY: allocated by `apu_alloc`.
        unsafe { VirtualFree(addr, 0, MEM_RELEASE) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn apu_is_valid(_addr: u64) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn apu_identity(addr: u64) -> u64 {
    addr
}

pub fn resolve(dll: &str, sym: &ImportSymbol<'_>) -> Option<usize> {
    let lower = dll.to_ascii_lowercase();
    match (lower.as_str(), sym) {
        ("gameinput.dll", ImportSymbol::Ordinal(1)) => Some(game_input_create as *const () as usize),
        ("xaudio2_9.dll", ImportSymbol::Ordinal(1)) => Some(xaudio2_create as *const () as usize),
        ("chad.dll", ImportSymbol::Name(_)) => Some(ret_ok as *const () as usize),
        ("xapu.dll", ImportSymbol::Name(_)) => Some(ret_ok as *const () as usize),
        ("acphal.dll", ImportSymbol::Name("ApuAlloc")) => Some(apu_alloc as *const () as usize),
        ("acphal.dll", ImportSymbol::Name("ApuFree")) => Some(apu_free as *const () as usize),
        ("acphal.dll", ImportSymbol::Name("ApuIsVirtualAddressValid")) => {
            Some(apu_is_valid as *const () as usize)
        }
        ("acphal.dll", ImportSymbol::Name("ApuMapApuAddress" | "ApuMapVirtualAddress")) => {
            Some(apu_identity as *const () as usize)
        }
        ("acphal.dll", ImportSymbol::Name(_)) => Some(ret_ok as *const () as usize),
        _ => None,
    }
}
