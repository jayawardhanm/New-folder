//! Xbox `xmem.dll` HLE implementation backed by native Win32 virtual memory.

use std::ffi::c_void;
use std::ptr;
use std::cell::Cell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_READWRITE,
    VirtualAlloc, VirtualFree, VirtualQuery,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const PAGE_64K: usize = 64 * 1024;
static TITLE_ALLOCATION_HOOKS: OnceLock<usize> = OnceLock::new();
static ALLOCATION_HOOK_LOGS: AtomicUsize = AtomicUsize::new(0);
static VIRTUAL_ALLOC2: OnceLock<usize> = OnceLock::new();

unsafe fn virtual_alloc2(
    address: *mut c_void,
    size: usize,
    allocation_type: u32,
    protection: u32,
) -> *mut c_void {
    type VirtualAlloc2Fn = unsafe extern "system" fn(
        *mut c_void, *mut c_void, usize, u32, u32, *mut c_void, u32,
    ) -> *mut c_void;
    let function = *VIRTUAL_ALLOC2.get_or_init(|| unsafe {
        let module = LoadLibraryA(c"kernelbase.dll".as_ptr().cast());
        if module.is_null() {
            return 0;
        }
        GetProcAddress(module, c"VirtualAlloc2".as_ptr().cast())
            .map_or(0, |proc| proc as usize)
    });
    if function == 0 {
        return ptr::null_mut();
    }
    let call: VirtualAlloc2Fn = unsafe { std::mem::transmute(function) };
    unsafe {
        call(
            GetCurrentProcess(),
            address,
            size,
            allocation_type,
            protection,
            ptr::null_mut(),
            0,
        )
    }
}

thread_local! {
    static IN_TITLE_HOOK: Cell<bool> = const { Cell::new(false) };
}

pub fn set_title_allocation_hooks(address: Option<usize>) {
    if let Some(address) = address.filter(|&a| a != 0) {
        let alloc = unsafe { *(address as *const usize) };
        let free = unsafe { *((address as *const usize).add(1)) };
        eprintln!("[HLE] installed title allocation hooks at {address:#x}: alloc={alloc:#x} free={free:#x}");
        let _ = TITLE_ALLOCATION_HOOKS.set(address);
    } else {
        eprintln!("[HLE] title allocation hooks export not found");
    }
}

pub fn title_allocate_callback() -> Option<usize> {
    TITLE_ALLOCATION_HOOKS
        .get()
        .map(|&table| unsafe { *(table as *const usize) })
        .filter(|&hook| hook != 0)
}

fn align_up(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_alloc(size: usize, attributes: u64) -> *mut c_void {
    type Hook = unsafe extern "system" fn(usize, u64) -> *mut c_void;
    if let Some(&table) = TITLE_ALLOCATION_HOOKS.get()
        && !IN_TITLE_HOOK.with(Cell::get)
    {
        let hook = unsafe { *(table as *const usize) };
        if hook != 0 {
            IN_TITLE_HOOK.with(|active| active.set(true));
            let result = unsafe { std::mem::transmute::<usize, Hook>(hook)(size, attributes) };
            IN_TITLE_HOOK.with(|active| active.set(false));
            if ALLOCATION_HOOK_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
                eprintln!("[HLE] title alloc hook size={size:#x} attrs={attributes:#x} -> {result:p}");
            }
            return result;
        }
    }
    let alloc_size = align_up(size.max(16), 4096);
    // SAFETY: standard Win32 VirtualAlloc for aligned title heap allocations.
    unsafe { VirtualAlloc(ptr::null(), alloc_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_alloc_default(size: usize, attributes: u64) -> *mut c_void {
    // SAFETY: delegates to `xmem_alloc`.
    unsafe { xmem_alloc(size, attributes) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_free(addr: *mut c_void, attributes: u64) {
    if !addr.is_null() {
        type Hook = unsafe extern "system" fn(*mut c_void, u64);
        if let Some(&table) = TITLE_ALLOCATION_HOOKS.get()
            && !IN_TITLE_HOOK.with(Cell::get)
        {
            let hook = unsafe { *((table as *const usize).add(1)) };
            if hook != 0 {
                IN_TITLE_HOOK.with(|active| active.set(true));
                unsafe { std::mem::transmute::<usize, Hook>(hook)(addr, attributes) };
                IN_TITLE_HOOK.with(|active| active.set(false));
                return;
            }
        }
        // SAFETY: `addr` was returned by `VirtualAlloc`.
        unsafe { VirtualFree(addr, 0, MEM_RELEASE) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_free_default(addr: *mut c_void, attributes: u64) {
    // SAFETY: delegates to `xmem_free`.
    unsafe { xmem_free(addr, attributes) };
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_virtual_alloc(
    addr: *mut c_void,
    size: usize,
    alloc_type: u32,
    _flags: u64,
    protect: u32,
) -> *mut c_void {
    const MEM_RESERVE_PLACEHOLDER: u32 = 0x0004_0000;
    const MEM_REPLACE_PLACEHOLDER: u32 = 0x0000_4000;
    const MEM_PHYSICAL_XBOX: u32 = 0x0040_0000;
    let size = align_up(size.max(4096), PAGE_64K);
    let low_protection = protect & 0xFF;
    let protection = match low_protection {
        0x01 | 0x02 | 0x04 | 0x10 | 0x20 | 0x40 => low_protection,
        _ => PAGE_READWRITE,
    };

    // Xbox physical reservations are address-space placeholders on PC; later
    // XMemVirtualAlloc calls replace their subranges with committed pages.
    if (alloc_type & MEM_RESERVE_PLACEHOLDER) != 0
        || ((alloc_type & MEM_PHYSICAL_XBOX) != 0
            && (alloc_type & MEM_RESERVE) != 0
            && (alloc_type & MEM_COMMIT) == 0)
    {
        let reserved = unsafe {
            virtual_alloc2(
                addr,
                size,
                MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
                0x01, // PAGE_NOACCESS
            )
        };
        if !reserved.is_null() {
            eprintln!("[HLE] reserved Xbox physical range {reserved:p} size={size:#x}");
            return reserved;
        }
    }
    if (alloc_type & MEM_REPLACE_PLACEHOLDER) != 0 {
        let replaced = unsafe {
            virtual_alloc2(
                addr,
                size,
                MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER,
                protection,
            )
        };
        if !replaced.is_null() {
            if ALLOCATION_HOOK_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
                eprintln!("[HLE] replaced Xbox memory placeholder {addr:p} size={size:#x}");
            }
            return replaced;
        }
        eprintln!("[HLE] VirtualAlloc2 placeholder replacement failed addr={addr:p} size={size:#x}");
    }
    // Strip Xbox-specific page/memory flags (e.g. 0x20400000 for 64K/graphics pages)
    // down to valid Win32 VirtualAlloc flags.
    const WIN32_ALLOC_MASK: u32 = MEM_COMMIT | MEM_RESERVE | 0x0008_0000 | 0x0010_0000;
    let mut ty = alloc_type & WIN32_ALLOC_MASK;
    if (ty & (MEM_COMMIT | MEM_RESERVE)) == 0 {
        ty |= MEM_RESERVE | MEM_COMMIT;
    }
    // Strip Xbox-specific protection flags, keep valid Win32 page protections.
    let prot = if (ty & MEM_COMMIT) == 0 {
        // Reserve-only: Windows requires a valid access protection; PAGE_NOACCESS is always valid.
        0x01 // PAGE_NOACCESS
    } else {
        match protect & 0xFF {
            0x01 | 0x02 | 0x04 | 0x10 | 0x20 | 0x40 => protect & 0xFF,
            _ => PAGE_READWRITE,
        }
    };
    if size >= 2 * 1024 * 1024 {
        eprintln!(
            "[HLE] XMemVirtualAlloc large request addr={addr:p} size={size:#x} alloc_type={alloc_type:#x} flags={_flags:#x} protect={protect:#x}"
        );
    }
    // SAFETY: sanitized Win32 `VirtualAlloc` call.
    let res = unsafe { VirtualAlloc(addr, size, ty, prot) };
    if !res.is_null() {
        return res;
    }
    if !addr.is_null() {
        // Xbox often splits a reserved region and re-allocates sub-ranges at fixed `addr`.
        if (ty & MEM_COMMIT) != 0 {
            let res2 = unsafe { VirtualAlloc(addr, size, MEM_COMMIT, prot) };
            if !res2.is_null() {
                return res2;
            }
        } else {
            let mut mbi = std::mem::MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
            if unsafe { VirtualQuery(addr, mbi.as_mut_ptr(), size_of::<MEMORY_BASIC_INFORMATION>()) } != 0 {
                let mbi = unsafe { mbi.assume_init() };
                if mbi.State != 0x10000 {
                    // Already reserved/committed at `addr`.
                    return addr;
                }
            }
        }
    }
    eprintln!(
        "[HLE] XMemVirtualAlloc failed addr={:p} size={size:#x} alloc_type={alloc_type:#x} protect={protect:#x}",
        addr
    );
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hle_virtual_free(
    addr: *mut c_void,
    size: usize,
    free_type: u32,
) -> i32 {
    if addr.is_null() {
        return 0;
    }
    const MEM_PRESERVE_PLACEHOLDER: u32 = 0x0000_0002;
    if (free_type & MEM_RELEASE) != 0 && (free_type & MEM_PRESERVE_PLACEHOLDER) != 0 && size != 0 {
        // The Xbox allocator splits its large reservations before replacing
        // individual subranges. Preserve the surrounding placeholder pieces.
        return unsafe { VirtualFree(addr, size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) };
    }
    let ft = free_type & !0x2;
    if (ft & MEM_RELEASE) != 0 && size != 0 {
        // Xbox sub-range release/split: decommit the sub-range while keeping the outer
        // reservation intact so subsequent sub-range `XMemVirtualAlloc`/`XMemMapPhysicalPages`
        // calls can commit inside it cleanly.
        let _ = unsafe { VirtualFree(addr, size, MEM_DECOMMIT) };
        return 1;
    }
    unsafe { VirtualFree(addr, size, ft) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_virtual_query(
    _process: *mut c_void,
    addr: *const c_void,
    info: *mut MEMORY_BASIC_INFORMATION,
) -> i32 {
    // SAFETY: direct Win32 `VirtualQuery` passthrough.
    (unsafe { VirtualQuery(addr, info, size_of::<MEMORY_BASIC_INFORMATION>()) } != 0) as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_allocate_physical_pages(
    _flags: u64,
    num_pages: *mut usize,
    page_array: *mut usize,
) -> i32 {
    if num_pages.is_null() || page_array.is_null() {
        return 0; // FALSE
    }
    // SAFETY: caller provides valid pointers for `num_pages` and `page_array`.
    let count = unsafe { *num_pages };
    for i in 0..count {
        // SAFETY: commit a 64 KiB backing page per physical page token.
        let p = unsafe { VirtualAlloc(ptr::null(), PAGE_64K, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
        if p.is_null() {
            return 0; // FALSE
        }
        // SAFETY: `page_array` has `count` slots.
        unsafe { *page_array.add(i) = p as usize };
    }
    1 // TRUE
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_free_physical_pages(num_pages: usize, page_array: *const usize) -> i32 {
    if page_array.is_null() {
        return 1;
    }
    for i in 0..num_pages {
        // SAFETY: `page_array` has `num_pages` slots allocated by `xmem_allocate_physical_pages`.
        let p = unsafe { *page_array.add(i) } as *mut c_void;
        if !p.is_null() {
            // SAFETY: allocated with `VirtualAlloc`.
            unsafe { VirtualFree(p, 0, MEM_RELEASE) };
        }
    }
    1 // TRUE
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_map_physical_pages(
    virt_addr: *mut c_void,
    num_pages: usize,
    page_array: *const usize,
) -> *mut c_void {
    if num_pages == 0 {
        return virt_addr;
    }
    let total = num_pages * PAGE_64K;
    // SAFETY: reserve+commit virtual range if not already committed, then copy initial contents if any.
    let res = unsafe { VirtualAlloc(virt_addr, total, MEM_COMMIT, PAGE_READWRITE) };
    let target = if !res.is_null() {
        res
    } else {
        let res2 = unsafe { VirtualAlloc(virt_addr, total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
        if !res2.is_null() {
            res2
        } else {
            // Fallback: commit page-by-page in case `virt_addr..virt_addr+total` spans reservations.
            for i in 0..num_pages {
                let page_va = unsafe { (virt_addr as *mut u8).add(i * PAGE_64K) }.cast();
                let r = unsafe { VirtualAlloc(page_va, PAGE_64K, MEM_COMMIT, PAGE_READWRITE) };
                if r.is_null() {
                    let r2 = unsafe { VirtualAlloc(page_va, PAGE_64K, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
                    if r2.is_null() {
                        eprintln!(
                            "[HLE] XMemMapPhysicalPages failed virt_addr={:p} num_pages={num_pages} total={total:#x}",
                            virt_addr
                        );
                        return ptr::null_mut();
                    }
                }
            }
            virt_addr
        }
    };
    if !page_array.is_null() {
        for i in 0..num_pages {
            let src = unsafe { *page_array.add(i) } as *const u8;
            if !src.is_null() {
                unsafe { ptr::copy_nonoverlapping(src, (target as *mut u8).add(i * PAGE_64K), PAGE_64K) };
            }
        }
    }
    target
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_map_physical_pages_scatter(
    addresses: *const *mut c_void,
    num_pages: usize,
    page_array: *const usize,
) -> i32 {
    if addresses.is_null() {
        return 0;
    }
    for i in 0..num_pages {
        // SAFETY: `addresses` has `num_pages` entries.
        let va = unsafe { *addresses.add(i) };
        let p = if page_array.is_null() {
            ptr::null()
        } else {
            unsafe { page_array.add(i) }
        };
        if unsafe { xmem_map_physical_pages(va, 1, p) }.is_null() {
            return 0;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_transfer_memory(_kind: u32, _bytes: usize) -> i32 {
    let _ = MEM_DECOMMIT;
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_get_working_set_statistics(_which: u32, out: *mut c_void) -> i32 {
    if out.is_null() {
        return 0;
    }
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn xmem_is_tools_mem_available() -> i32 {
    0
}

pub fn resolve(name: &str) -> Option<usize> {
    let addr = match name {
        "XMemAlloc" => xmem_alloc as *const () as usize,
        "XMemAllocDefault" => xmem_alloc_default as *const () as usize,
        "XMemFree" => xmem_free as *const () as usize,
        "XMemFreeDefault" => xmem_free_default as *const () as usize,
        "XMemVirtualAlloc" => xmem_virtual_alloc as *const () as usize,
        "XMemVirtualQuery" => xmem_virtual_query as *const () as usize,
        "XMemAllocatePhysicalPages" => xmem_allocate_physical_pages as *const () as usize,
        "XMemFreePhysicalPages" => xmem_free_physical_pages as *const () as usize,
        "XMemMapPhysicalPages" => xmem_map_physical_pages as *const () as usize,
        "XMemMapPhysicalPagesScatter" => xmem_map_physical_pages_scatter as *const () as usize,
        "XMemTransferMemory" => xmem_transfer_memory as *const () as usize,
        "XMemGetWorkingSetStatistics" => xmem_get_working_set_statistics as *const () as usize,
        "XMemIsToolsMemAvailable" => xmem_is_tools_mem_available as *const () as usize,
        _ => return None,
    };
    Some(addr)
}
