//! PC-native `ID3D12GraphicsCommandList` / `ID3D12GraphicsCommandListX` COM wrapper.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};

use windows::Win32::Graphics::Direct3D12::*;
use windows::core::{GUID, Interface};

#[repr(transparent)]
struct SyncVtbl<const N: usize>([*const c_void; N]);
// SAFETY: static COM vtables are immutable and thread-safe.
unsafe impl<const N: usize> Sync for SyncVtbl<N> {}

#[repr(C)]
pub struct XboxCommandListX {
    vtable: *const *const c_void,
    ref_count: AtomicU32,
    pub list: ID3D12GraphicsCommandList,
    _alloc: ID3D12CommandAllocator,
}

unsafe extern "system" fn qi(
    this: *mut XboxCommandListX,
    _riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if !ppv.is_null() {
        // SAFETY: valid out pointer.
        unsafe { *ppv = this.cast() };
    }
    // SAFETY: `this` is valid `XboxCommandListX`.
    unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) };
    0
}

unsafe extern "system" fn addref(this: *mut XboxCommandListX) -> u32 {
    // SAFETY: `this` is valid `XboxCommandListX`.
    unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) + 1 }
}

unsafe extern "system" fn release(this: *mut XboxCommandListX) -> u32 {
    // SAFETY: `this` is valid `XboxCommandListX`.
    let prev = unsafe { (*this).ref_count.fetch_sub(1, Ordering::AcqRel) };
    if prev == 1 {
        // SAFETY: boxed via `Box::into_raw`.
        unsafe { drop(Box::from_raw(this)) };
    }
    prev.saturating_sub(1)
}

unsafe extern "system" fn close(this: *mut XboxCommandListX) -> i32 {
    // SAFETY: valid `XboxCommandListX`.
    let res = unsafe { (*this).list.Close() };
    match res {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[GPU] CommandListX::Close failed: {:#x}", e.code().0);
            e.code().0
        }
    }
}

unsafe extern "system" fn reset(
    this: *mut XboxCommandListX,
    alloc: *mut c_void,
    pso: *mut c_void,
) -> i32 {
    // SAFETY: valid `XboxCommandListX` and borrowed COM pointers.
    unsafe {
        let a_ref = if alloc.is_null() {
            std::mem::ManuallyDrop::new((*this)._alloc.clone())
        } else {
            std::mem::ManuallyDrop::new(ID3D12CommandAllocator::from_raw(alloc))
        };
        let p_opt = if pso.is_null() {
            None
        } else {
            Some(std::mem::ManuallyDrop::new(ID3D12PipelineState::from_raw(pso)))
        };
        (*this)
            .list
            .Reset(&*a_ref, p_opt.as_ref().map(|p| &**p))
            .map_or_else(|e| e.code().0, |()| 0)
    }
}

unsafe extern "system" fn unimpl_list_slot<const SLOT: usize>() -> i32 {
    eprintln!("[GPU] XboxCommandListX unimplemented slot {SLOT} (offset {:#x})", SLOT * 8);
    0
}

unsafe extern "system" fn ok_list_slot() -> i32 {
    0
}

macro_rules! list_vtbl_160 {
    ($($s:expr),* $(,)?) => {
        SyncVtbl([
            qi as *const c_void,              // 0
            addref as *const c_void,          // 1
            release as *const c_void,         // 2
            ok_list_slot as *const c_void,    // 3: GetPrivateData
            ok_list_slot as *const c_void,    // 4: SetPrivateData
            ok_list_slot as *const c_void,    // 5: SetPrivateDataInterface
            ok_list_slot as *const c_void,    // 6: SetName
            ok_list_slot as *const c_void,    // 7: GetDevice
            ok_list_slot as *const c_void,    // 8: GetType
            close as *const c_void,           // 9: Close
            reset as *const c_void,           // 10: Reset
            $(unimpl_list_slot::<$s> as *const c_void,)*
        ])
    };
}

static LIST_VTBL: SyncVtbl<160> = {
    let mut tbl = list_vtbl_160!(
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
        43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
        59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
        75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
        91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106,
        107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
        123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138,
        139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154,
        155, 156, 157, 158, 159
    );
    // Xbox GPU cache sync/flush slots: no-ops on PC D3D12.
    tbl.0[131] = ok_list_slot as *const c_void;
    tbl.0[132] = ok_list_slot as *const c_void;
    tbl
};

pub fn wrap_command_list(list: ID3D12GraphicsCommandList, alloc: ID3D12CommandAllocator) -> *mut c_void {
    Box::into_raw(Box::new(XboxCommandListX {
        vtable: LIST_VTBL.0.as_ptr(),
        ref_count: AtomicU32::new(1),
        list,
        _alloc: alloc,
    }))
    .cast()
}
