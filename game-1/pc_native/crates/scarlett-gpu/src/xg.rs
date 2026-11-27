//! `xg_xs.dll` (`XGTextureAddressComputer`) COM wrapper for PC-native texture layout queries.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};

#[repr(transparent)]
struct SyncVtbl<const N: usize>([*const c_void; N]);
// SAFETY: function pointers in static COM vtables are immutable and thread-safe.
unsafe impl<const N: usize> Sync for SyncVtbl<N> {}

#[repr(C)]
pub struct TextureComputer {
    vtable: *const *const c_void,
    ref_count: AtomicU32,
}

unsafe extern "system" fn qi(
    this: *mut TextureComputer,
    _riid: *const c_void,
    ppv: *mut *mut c_void,
) -> i32 {
    if !ppv.is_null() {
        // SAFETY: valid out pointer.
        unsafe { *ppv = this.cast() };
    }
    // SAFETY: `this` is valid `TextureComputer`.
    unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) };
    0
}

unsafe extern "system" fn addref(this: *mut TextureComputer) -> u32 {
    // SAFETY: `this` is valid `TextureComputer`.
    unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) + 1 }
}

unsafe extern "system" fn release(this: *mut TextureComputer) -> u32 {
    // SAFETY: `this` is valid `TextureComputer`.
    let prev = unsafe { (*this).ref_count.fetch_sub(1, Ordering::AcqRel) };
    if prev == 1 {
        // SAFETY: boxed via `Box::into_raw`.
        unsafe { drop(Box::from_raw(this)) };
    }
    prev.saturating_sub(1)
}

unsafe extern "system" fn stub_ok() -> i32 {
    0
}

static COMPUTER_VTBL: SyncVtbl<16> = SyncVtbl([
    qi as *const c_void,
    addref as *const c_void,
    release as *const c_void,
    stub_ok as *const c_void, // GetResourceLayout
    stub_ok as *const c_void, // GetResourceSizeBytes
    stub_ok as *const c_void, // GetResourceBaseAlignmentBytes
    stub_ok as *const c_void, // GetMipLevelOffsetBytes
    stub_ok as *const c_void, // GetTexelElementOffsetBytes
    stub_ok as *const c_void, // GetTexelCoordinate
    stub_ok as *const c_void, // CopyIntoSubresource
    stub_ok as *const c_void, // CopyFromSubresource
    stub_ok as *const c_void, // GetResourceTiling
    stub_ok as *const c_void,
    stub_ok as *const c_void,
    stub_ok as *const c_void,
    stub_ok as *const c_void,
]);

pub fn create_texture_computer() -> *mut TextureComputer {
    Box::into_raw(Box::new(TextureComputer {
        vtable: COMPUTER_VTBL.0.as_ptr(),
        ref_count: AtomicU32::new(1),
    }))
}
