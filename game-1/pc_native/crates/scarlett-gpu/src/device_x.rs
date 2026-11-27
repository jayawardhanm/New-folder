//! PC-native `ID3D12Device` / `ID3D12DeviceX` COM wrapper backed by `NativeDevice`.
//!
//! All GPU resources, queues, fences, and descriptor heaps map directly to
//! native PC D3D12 objects without UMA shared-memory shadow tracking.

use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicU32, Ordering};

use windows::Win32::Graphics::Direct3D12::*;
use windows::core::{GUID, Interface};

use crate::NativeDevice;

static GLOBAL_DEVICE: OnceLock<NativeDevice> = OnceLock::new();
static TITLE_ALLOCATOR: OnceLock<usize> = OnceLock::new();
static TITLE_RESOURCE_ALLOCATIONS: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();

pub fn set_title_allocator(allocator: usize) {
    if allocator != 0 {
        eprintln!("[GPU] installed title allocator callback {allocator:#x}");
        let _ = TITLE_ALLOCATOR.set(allocator);
    }
}

pub fn init_global_device() -> anyhow::Result<&'static NativeDevice> {
    if let Some(d) = GLOBAL_DEVICE.get() {
        return Ok(d);
    }
    let dev = NativeDevice::create_high_performance()?;
    let _ = GLOBAL_DEVICE.set(dev);
    Ok(GLOBAL_DEVICE.get().expect("initialized"))
}

#[repr(transparent)]
struct SyncVtbl<const N: usize>([*const c_void; N]);
// SAFETY: function pointers in static COM vtables are immutable and thread-safe.
unsafe impl<const N: usize> Sync for SyncVtbl<N> {}

#[repr(C)]
pub struct XboxDeviceX {
    vtable: *const *const c_void,
    ref_count: AtomicU32,
    device: ID3D12Device8,
}

const IID_IDXGI_DEVICE: GUID = GUID::from_u128(0x54ec77fa_1377_44e6_8c32_88fd5f44c84c);

#[repr(C)]
struct DxgiDeviceStub {
    vtable: *const *const c_void,
    ref_count: AtomicU32,
}

unsafe extern "system" fn dxgi_qi(
    this: *mut DxgiDeviceStub,
    _riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if !ppv.is_null() {
        unsafe { *ppv = this.cast() };
    }
    unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) };
    0
}

unsafe extern "system" fn dxgi_addref(this: *mut DxgiDeviceStub) -> u32 {
    unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) + 1 }
}

unsafe extern "system" fn dxgi_release(this: *mut DxgiDeviceStub) -> u32 {
    let prev = unsafe { (*this).ref_count.fetch_sub(1, Ordering::AcqRel) };
    if prev == 1 {
        unsafe { drop(Box::from_raw(this)) };
    }
    prev.saturating_sub(1)
}

unsafe extern "system" fn dxgi_get_adapter(
    _this: *mut DxgiDeviceStub,
    ppv: *mut *mut c_void,
) -> i32 {
    if ppv.is_null() {
        return -2147467261;
    }
    if let Some(dev) = GLOBAL_DEVICE.get() {
        unsafe { *ppv = dev.adapter.clone().into_raw() };
        return 0;
    }
    -2147467259
}

unsafe extern "system" fn dxgi_ok() -> i32 {
    0
}

static DXGI_DEVICE_VTBL: SyncVtbl<12> = SyncVtbl([
    dxgi_qi as *const c_void,
    dxgi_addref as *const c_void,
    dxgi_release as *const c_void,
    dxgi_ok as *const c_void,          // SetPrivateData
    dxgi_ok as *const c_void,          // SetPrivateDataInterface
    dxgi_ok as *const c_void,          // GetPrivateData
    dxgi_ok as *const c_void,          // GetParent
    dxgi_get_adapter as *const c_void, // GetAdapter (slot 7 = +0x38)
    dxgi_ok as *const c_void,
    dxgi_ok as *const c_void,
    dxgi_ok as *const c_void,
    dxgi_ok as *const c_void,
]);

unsafe extern "system" fn qi(
    this: *mut XboxDeviceX,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if ppv.is_null() {
        return -2147467261;
    }
    if !riid.is_null() && unsafe { *riid } == IID_IDXGI_DEVICE {
        let obj = Box::into_raw(Box::new(DxgiDeviceStub {
            vtable: DXGI_DEVICE_VTBL.0.as_ptr(),
            ref_count: AtomicU32::new(1),
        }));
        unsafe { *ppv = obj.cast() };
        return 0;
    }
    // SAFETY: valid out pointer.
    unsafe { *ppv = this.cast() };
    // SAFETY: `this` is valid `XboxDeviceX`.
    unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) };
    0
}

unsafe extern "system" fn addref(this: *mut XboxDeviceX) -> u32 {
    // SAFETY: `this` is valid `XboxDeviceX`.
    unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) + 1 }
}

unsafe extern "system" fn release(this: *mut XboxDeviceX) -> u32 {
    // SAFETY: `this` is valid `XboxDeviceX`.
    let prev = unsafe { (*this).ref_count.fetch_sub(1, Ordering::AcqRel) };
    if prev == 1 {
        // SAFETY: boxed via `Box::into_raw`.
        unsafe { drop(Box::from_raw(this)) };
    }
    prev.saturating_sub(1)
}

unsafe extern "system" fn get_node_count(_this: *mut XboxDeviceX) -> u32 {
    1
}

unsafe extern "system" fn create_command_queue(
    this: *mut XboxDeviceX,
    desc: *const D3D12_COMMAND_QUEUE_DESC,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if desc.is_null() || riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    // SAFETY: valid `XboxDeviceX`, `desc`, `riid`, `ppv`.
    unsafe {
        let dev = &(*this).device;
        let d = &*desc;
        eprintln!("[GPU] CreateCommandQueue type={:?} prio={} flags={:?} node={}", d.Type, d.Priority, d.Flags, d.NodeMask);
        let q: Result<ID3D12CommandQueue, _> = dev.CreateCommandQueue(d);
        match q {
            Ok(q) => {
                *ppv = q.into_raw();
                0
            }
            Err(e) => {
                eprintln!("[GPU] CreateCommandQueue failed: {:?}", e);
                e.code().0
            }
        }
    }
}

unsafe extern "system" fn create_command_allocator(
    this: *mut XboxDeviceX,
    ty: D3D12_COMMAND_LIST_TYPE,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    // SAFETY: valid `XboxDeviceX`, `riid`, `ppv`.
    unsafe {
        let dev = &(*this).device;
        let alloc: Result<ID3D12CommandAllocator, _> = dev.CreateCommandAllocator(ty);
        match alloc {
            Ok(a) => {
                *ppv = a.into_raw();
                0
            }
            Err(e) => e.code().0,
        }
    }
}

unsafe extern "system" fn create_graphics_pipeline_state(
    this: *mut XboxDeviceX,
    desc: *const D3D12_GRAPHICS_PIPELINE_STATE_DESC,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if desc.is_null() || riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    // SAFETY: valid pointers.
    unsafe {
        let dev = &(*this).device;
        match dev.CreateGraphicsPipelineState::<ID3D12PipelineState>(&*desc) {
            Ok(p) => {
                *ppv = p.into_raw();
                0
            }
            Err(e) => e.code().0,
        }
    }
}

unsafe extern "system" fn create_compute_pipeline_state(
    this: *mut XboxDeviceX,
    desc: *const D3D12_COMPUTE_PIPELINE_STATE_DESC,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if desc.is_null() || riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    // SAFETY: valid pointers.
    unsafe {
        let dev = &(*this).device;
        match dev.CreateComputePipelineState::<ID3D12PipelineState>(&*desc) {
            Ok(p) => {
                *ppv = p.into_raw();
                0
            }
            Err(e) => {
                eprintln!("[GPU] CreateComputePipelineState failed: {:?}", e);
                e.code().0
            }
        }
    }
}

unsafe extern "system" fn create_graphics_pipeline_state_x(
    this: *mut XboxDeviceX,
    desc: *const D3D12_GRAPHICS_PIPELINE_STATE_DESC,
    _flags: u64,
    _cache: u64,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    eprintln!("[GPU] CreateGraphicsPipelineStateX desc={desc:p} riid={riid:p} ppv={ppv:p}");
    unsafe { create_graphics_pipeline_state(this, desc, riid, ppv) }
}

unsafe extern "system" fn create_command_list(
    this: *mut XboxDeviceX,
    node_mask: u32,
    ty: D3D12_COMMAND_LIST_TYPE,
    alloc: *mut c_void,
    init_state: *mut c_void,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if alloc.is_null() || riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    // SAFETY: borrowed COM pointers from title.
    unsafe {
        let alloc_ref = std::mem::ManuallyDrop::new(ID3D12CommandAllocator::from_raw(alloc));
        let pso_opt = if init_state.is_null() {
            None
        } else {
            Some(std::mem::ManuallyDrop::new(ID3D12PipelineState::from_raw(init_state)))
        };
        let dev = &(*this).device;
        let res: Result<ID3D12GraphicsCommandList, _> = dev.CreateCommandList(
            node_mask,
            ty,
            &*alloc_ref,
            pso_opt.as_ref().map(|p| &**p),
        );
        match res {
            Ok(l) => {
                *ppv = l.into_raw();
                0
            }
            Err(e) => e.code().0,
        }
    }
}

unsafe extern "system" fn check_feature_support(
    this: *mut XboxDeviceX,
    feature: D3D12_FEATURE,
    data: *mut c_void,
    size: u32,
) -> i32 {
    // SAFETY: valid `XboxDeviceX` and caller buffer.
    unsafe {
        (*this)
            .device
            .CheckFeatureSupport(feature, data, size)
            .map_or_else(|e| e.code().0, |()| 0)
    }
}

struct PlacedHeapRange {
    placed_start: usize,
    placed_end: usize,
    real_cpu_start: usize,
}

static PLACED_HEAPS: OnceLock<Mutex<Vec<PlacedHeapRange>>> = OnceLock::new();

fn placed_heaps() -> &'static Mutex<Vec<PlacedHeapRange>> {
    PLACED_HEAPS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn translate_cpu_handle(h: D3D12_CPU_DESCRIPTOR_HANDLE) -> D3D12_CPU_DESCRIPTOR_HANDLE {
    if let Ok(guard) = placed_heaps().lock() {
        for r in guard.iter() {
            if h.ptr >= r.placed_start && h.ptr < r.placed_end {
                return D3D12_CPU_DESCRIPTOR_HANDLE {
                    ptr: r.real_cpu_start + (h.ptr - r.placed_start),
                };
            }
        }
    }
    h
}

fn sanitize_resource_desc(src: &D3D12_RESOURCE_DESC) -> D3D12_RESOURCE_DESC {
    let mut d = *src;
    d.Flags = D3D12_RESOURCE_FLAGS(d.Flags.0 & 0x3F);
    if d.Dimension == D3D12_RESOURCE_DIMENSION_BUFFER {
        d.Alignment = 0;
        d.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
        d.SampleDesc.Count = 1;
        d.SampleDesc.Quality = 0;
    }
    d
}

#[repr(C)]
pub struct XboxDescriptorHeapX {
    vtable: *const *const c_void,
    ref_count: AtomicU32,
    inner: ID3D12DescriptorHeap,
    placed_va: u64,
}

static DESCR_HEAP_VTBL: SyncVtbl<11> = SyncVtbl([
    heap_qi as *const c_void,              // 0: QueryInterface
    heap_addref as *const c_void,          // 1: AddRef
    heap_release as *const c_void,         // 2: Release
    stub_ok_device as *const c_void,       // 3: GetPrivateData
    stub_ok_device as *const c_void,       // 4: SetPrivateData
    stub_ok_device as *const c_void,       // 5: SetPrivateDataInterface
    stub_ok_device as *const c_void,       // 6: SetName
    stub_ok_device as *const c_void,       // 7: GetDevice
    heap_get_desc as *const c_void,        // 8: GetDesc
    heap_get_cpu_handle as *const c_void,  // 9: GetCPUDescriptorHandleForHeapStart
    heap_get_gpu_handle as *const c_void,  // 10: GetGPUDescriptorHandleForHeapStart
]);

unsafe extern "system" fn heap_qi(
    this: *mut XboxDescriptorHeapX,
    _riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if ppv.is_null() {
        return -2147467261;
    }
    unsafe {
        *ppv = this.cast();
        heap_addref(this);
    }
    0
}

unsafe extern "system" fn heap_addref(this: *mut XboxDescriptorHeapX) -> u32 {
    unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) + 1 }
}

unsafe extern "system" fn heap_release(this: *mut XboxDescriptorHeapX) -> u32 {
    let prev = unsafe { (*this).ref_count.fetch_sub(1, Ordering::Release) };
    if prev == 1 {
        std::sync::atomic::fence(Ordering::Acquire);
        drop(unsafe { Box::from_raw(this) });
        return 0;
    }
    prev - 1
}

unsafe extern "system" fn heap_get_desc(
    out: *mut D3D12_DESCRIPTOR_HEAP_DESC,
    this: *mut XboxDescriptorHeapX,
) -> *mut D3D12_DESCRIPTOR_HEAP_DESC {
    if !out.is_null() {
        let desc = unsafe { (*this).inner.GetDesc() };
        unsafe { *out = desc };
    }
    out
}

unsafe extern "system" fn heap_get_cpu_handle(this: *mut XboxDescriptorHeapX) -> usize {
    // SAFETY: Xbox GDK returns `D3D12_CPU_DESCRIPTOR_HANDLE.ptr` directly in `rax`.
    // For placed Xbox descriptor heaps, the title asserts `GetCPUDescriptorHandleForHeapStart() == placed_va`.
    unsafe {
        if (*this).placed_va != 0 {
            (*this).placed_va as usize
        } else {
            (*this).inner.GetCPUDescriptorHandleForHeapStart().ptr
        }
    }
}

unsafe extern "system" fn heap_get_gpu_handle(this: *mut XboxDescriptorHeapX) -> u64 {
    // SAFETY: Xbox GDK returns `D3D12_GPU_DESCRIPTOR_HANDLE.ptr` directly in `rax`.
    unsafe {
        if (*this).placed_va != 0 {
            (*this).placed_va
        } else {
            (*this).inner.GetGPUDescriptorHandleForHeapStart().ptr
        }
    }
}

unsafe extern "system" fn create_descriptor_heap(
    this: *mut XboxDeviceX,
    desc: *const D3D12_DESCRIPTOR_HEAP_DESC,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if desc.is_null() || riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    // SAFETY: valid pointers.
    unsafe {
        let dev = &(*this).device;
        let mut d = *desc;
        // Xbox `D3D12_DESCRIPTOR_HEAP_DESC` carries an optional placed VA at +0x10.
        let candidate_va = *(desc.cast::<u64>().add(2));
        let placed_va = if candidate_va >= 0x10000 && candidate_va < 0x7FFF_FFFF_FFFF {
            candidate_va
        } else {
            0
        };
        if (d.Flags.0 & D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE.0) != 0 {
            if d.Type == D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV && d.NumDescriptors > 1_000_000 {
                d.NumDescriptors = 1_000_000;
            } else if d.Type == D3D12_DESCRIPTOR_HEAP_TYPE_SAMPLER && d.NumDescriptors > 2048 {
                d.NumDescriptors = 2048;
            }
        }
        match dev.CreateDescriptorHeap::<ID3D12DescriptorHeap>(&d) {
            Ok(h) => {
                eprintln!("[GPU] CreateDescriptorHeap type={} count={} placed_va={placed_va:#x}", d.Type.0, d.NumDescriptors);
                if placed_va != 0 {
                    let inc = dev.GetDescriptorHandleIncrementSize(d.Type) as usize;
                    let real_cpu_start = h.GetCPUDescriptorHandleForHeapStart().ptr;
                    let span = (d.NumDescriptors as usize).saturating_mul(inc);
                    if let Ok(mut guard) = placed_heaps().lock() {
                        guard.push(PlacedHeapRange {
                            placed_start: placed_va as usize,
                            placed_end: (placed_va as usize).saturating_add(span),
                            real_cpu_start,
                        });
                    }
                }
                let boxed = Box::new(XboxDescriptorHeapX {
                    vtable: DESCR_HEAP_VTBL.0.as_ptr(),
                    ref_count: AtomicU32::new(1),
                    inner: h,
                    placed_va,
                });
                let ptr = Box::into_raw(boxed).cast();
                *ppv = ptr;
                0
            }
            Err(e) => {
                eprintln!(
                    "[GPU] CreateDescriptorHeap type={} num={} flags={} failed: {:?}",
                    d.Type.0, d.NumDescriptors, d.Flags.0, e
                );
                e.code().0
            }
        }
    }
}

unsafe extern "system" fn get_descriptor_handle_increment_size(
    this: *mut XboxDeviceX,
    ty: D3D12_DESCRIPTOR_HEAP_TYPE,
) -> u32 {
    // SAFETY: valid `XboxDeviceX`.
    unsafe { (*this).device.GetDescriptorHandleIncrementSize(ty) }
}

unsafe extern "system" fn create_root_signature(
    this: *mut XboxDeviceX,
    node_mask: u32,
    blob: *const c_void,
    len: usize,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if blob.is_null() || riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    // SAFETY: valid blob slice and COM pointers.
    unsafe {
        let bytes = std::slice::from_raw_parts(blob.cast::<u8>(), len);
        match (*this).device.CreateRootSignature::<ID3D12RootSignature>(node_mask, bytes) {
            Ok(r) => {
                *ppv = r.into_raw();
                0
            }
            Err(e) => {
                eprintln!("[GPU] CreateRootSignature len={len} failed: {:?}", e);
                e.code().0
            }
        }
    }
}

unsafe extern "system" fn create_fence(
    this: *mut XboxDeviceX,
    initial: u64,
    flags: D3D12_FENCE_FLAGS,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    // SAFETY: valid pointers.
    unsafe {
        match (*this).device.CreateFence::<ID3D12Fence>(initial, flags) {
            Ok(f) => {
                *ppv = f.into_raw();
                0
            }
            Err(e) => e.code().0,
        }
    }
}

unsafe extern "system" fn get_device_removed_reason(this: *mut XboxDeviceX) -> i32 {
    // SAFETY: valid `XboxDeviceX`.
    unsafe {
        (*this)
            .device
            .GetDeviceRemovedReason()
            .map_or_else(|e| e.code().0, |()| 0)
    }
}

unsafe extern "system" fn create_command_queue_x(
    this: *mut XboxDeviceX,
    desc: *const D3D12_COMMAND_QUEUE_DESC,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if desc.is_null() || riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    // SAFETY: Xbox `D3D12_COMMAND_QUEUE_DESC_X` starts with `D3D12_COMMAND_LIST_TYPE` at offset 0.
    let pc_desc = D3D12_COMMAND_QUEUE_DESC {
        Type: unsafe { (*desc).Type },
        Priority: 0,
        Flags: D3D12_COMMAND_QUEUE_FLAG_NONE,
        NodeMask: 0,
    };
    // SAFETY: valid `XboxDeviceX`, `riid`, `ppv`.
    unsafe {
        let dev = &(*this).device;
        let res = dev.CreateCommandQueue::<ID3D12CommandQueue>(&pc_desc);
        eprintln!("[GPU] CreateCommandQueueX type={} -> {:?}", pc_desc.Type.0, res.as_ref().map(|_| "ok").map_err(|e| e.code().0));
        match res {
            Ok(q) => {
                *ppv = q.into_raw();
                0
            }
            Err(e) => e.code().0,
        }
    }
}

unsafe extern "system" fn create_command_list_x(
    this: *mut XboxDeviceX,
    desc: *const u32,
    _arg3: *const c_void,
    _arg4: usize,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if desc.is_null() || riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    // SAFETY: Xbox `D3D12XBOX_COMMAND_LIST_DESC` starts with `D3D12_COMMAND_LIST_TYPE`.
    let raw_ty = unsafe { *desc } as i32;
    let ty = D3D12_COMMAND_LIST_TYPE(if matches!(raw_ty, 0 | 1 | 2 | 3) { raw_ty } else { 0 });
    // SAFETY: Xbox `CreateCommandListX` returns an open command list ready for recording/`Close`.
    unsafe {
        let dev = &(*this).device;
        let alloc = match dev.CreateCommandAllocator::<ID3D12CommandAllocator>(ty) {
            Ok(a) => a,
            Err(e) => return e.code().0,
        };
        let res = dev.CreateCommandList::<_, _, ID3D12GraphicsCommandList>(0, ty, &alloc, None);
        if let Err(ref e) = res {
            eprintln!("[GPU] CreateCommandListX raw_ty={raw_ty} failed: {:#x}", e.code().0);
        }
        match res {
            Ok(l) => {
                *ppv = crate::cmd_list_x::wrap_command_list(l, alloc);
                0
            }
            Err(e) => e.code().0,
        }
    }
}

unsafe extern "system" fn get_custom_heap_properties(
    out: *mut D3D12_HEAP_PROPERTIES,
    _this: *mut XboxDeviceX,
    _node_mask: u32,
    heap_type: D3D12_HEAP_TYPE,
) -> *mut D3D12_HEAP_PROPERTIES {
    // SAFETY: Xbox GDK ABI passes `sret` in `rcx` (`out`) and `this` in `rdx` for `GetCustomHeapProperties`.
    if !out.is_null() {
        let props = if heap_type == D3D12_HEAP_TYPE_CUSTOM {
            D3D12_HEAP_PROPERTIES {
                Type: D3D12_HEAP_TYPE_CUSTOM,
                CPUPageProperty: D3D12_CPU_PAGE_PROPERTY_WRITE_COMBINE,
                MemoryPoolPreference: D3D12_MEMORY_POOL_L0,
                CreationNodeMask: 1,
                VisibleNodeMask: 1,
            }
        } else {
            D3D12_HEAP_PROPERTIES {
                Type: heap_type,
                CPUPageProperty: D3D12_CPU_PAGE_PROPERTY_UNKNOWN,
                MemoryPoolPreference: D3D12_MEMORY_POOL_UNKNOWN,
                CreationNodeMask: 1,
                VisibleNodeMask: 1,
            }
        };
        unsafe { *out = props };
    }
    out
}

unsafe extern "system" fn create_constant_buffer_view(
    this: *mut XboxDeviceX,
    desc: *const D3D12_CONSTANT_BUFFER_VIEW_DESC,
    dest: D3D12_CPU_DESCRIPTOR_HANDLE,
) {
    let opt = if desc.is_null() { None } else { Some(desc) };
    unsafe { (*this).device.CreateConstantBufferView(opt, translate_cpu_handle(dest)) };
}

unsafe extern "system" fn create_shader_resource_view(
    this: *mut XboxDeviceX,
    res: *mut c_void,
    desc: *const D3D12_SHADER_RESOURCE_VIEW_DESC,
    dest: D3D12_CPU_DESCRIPTOR_HANDLE,
) {
    let opt_res: Option<ID3D12Resource> = if res.is_null() {
        None
    } else {
        let r = unsafe { ID3D12Resource::from_raw_borrowed(&res) };
        r.cloned()
    };
    let opt_desc = if desc.is_null() { None } else { Some(desc) };
    unsafe {
        (*this)
            .device
            .CreateShaderResourceView(opt_res.as_ref(), opt_desc, translate_cpu_handle(dest));
    }
}

unsafe extern "system" fn create_unordered_access_view(
    this: *mut XboxDeviceX,
    res: *mut c_void,
    counter: *mut c_void,
    desc: *const D3D12_UNORDERED_ACCESS_VIEW_DESC,
    dest: D3D12_CPU_DESCRIPTOR_HANDLE,
) {
    let translated = translate_cpu_handle(dest);
    eprintln!("[GPU] CreateUAV resource={res:p} desc={desc:p} dest={:#x} translated={:#x}", dest.ptr, translated.ptr);
    let opt_res: Option<ID3D12Resource> = if res.is_null() {
        None
    } else {
        unsafe { ID3D12Resource::from_raw_borrowed(&res) }.cloned()
    };
    let opt_cnt: Option<ID3D12Resource> = if counter.is_null() {
        None
    } else {
        unsafe { ID3D12Resource::from_raw_borrowed(&counter) }.cloned()
    };
    let opt_desc = if desc.is_null() { None } else { Some(desc) };
    if !desc.is_null() {
        let words = unsafe { std::slice::from_raw_parts(desc.cast::<u64>(), 5) };
        eprintln!("[GPU] CreateUAV desc_words={words:#x?}");
    }
    if let Some(resource) = opt_res.as_ref() {
        let rd = unsafe { resource.GetDesc() };
        eprintln!("[GPU] CreateUAV resource_desc dim={} size={}x{} format={} flags={:#x}", rd.Dimension.0, rd.Width, rd.Height, rd.Format.0, rd.Flags.0);
    }
    unsafe {
        (*this).device.CreateUnorderedAccessView(
            opt_res.as_ref(),
            opt_cnt.as_ref(),
            opt_desc,
            translated,
        );
    }
}

unsafe extern "system" fn create_render_target_view(
    this: *mut XboxDeviceX,
    res: *mut c_void,
    desc: *const D3D12_RENDER_TARGET_VIEW_DESC,
    dest: D3D12_CPU_DESCRIPTOR_HANDLE,
) {
    let opt_res: Option<ID3D12Resource> = if res.is_null() {
        None
    } else {
        unsafe { ID3D12Resource::from_raw_borrowed(&res) }.cloned()
    };
    let opt_desc = if desc.is_null() { None } else { Some(desc) };
    unsafe {
        (*this)
            .device
            .CreateRenderTargetView(opt_res.as_ref(), opt_desc, translate_cpu_handle(dest));
    }
}

unsafe extern "system" fn create_depth_stencil_view(
    this: *mut XboxDeviceX,
    res: *mut c_void,
    desc: *const D3D12_DEPTH_STENCIL_VIEW_DESC,
    dest: D3D12_CPU_DESCRIPTOR_HANDLE,
) {
    let opt_res: Option<ID3D12Resource> = if res.is_null() {
        None
    } else {
        unsafe { ID3D12Resource::from_raw_borrowed(&res) }.cloned()
    };
    let opt_desc = if desc.is_null() { None } else { Some(desc) };
    unsafe {
        (*this)
            .device
            .CreateDepthStencilView(opt_res.as_ref(), opt_desc, translate_cpu_handle(dest));
    }
}

unsafe extern "system" fn create_sampler(
    this: *mut XboxDeviceX,
    desc: *const D3D12_SAMPLER_DESC,
    dest: D3D12_CPU_DESCRIPTOR_HANDLE,
) {
    if !desc.is_null() {
        unsafe { (*this).device.CreateSampler(&*desc, translate_cpu_handle(dest)) };
    }
}

unsafe extern "system" fn get_resource_allocation_info(
    out: *mut D3D12_RESOURCE_ALLOCATION_INFO,
    this: *mut XboxDeviceX,
    visible_mask: u32,
    num_descs: u32,
    descs: *const D3D12_RESOURCE_DESC,
) -> *mut D3D12_RESOURCE_ALLOCATION_INFO {
    // SAFETY: Xbox GDK passes `sret` in `rcx` (`out`) and `this` in `rdx`.
    if !out.is_null() {
        let info = if descs.is_null() || num_descs == 0 {
            D3D12_RESOURCE_ALLOCATION_INFO {
                SizeInBytes: 0,
                Alignment: 65536,
            }
        } else {
            let slice = unsafe { std::slice::from_raw_parts(descs, num_descs as usize) };
            let sanitized: Vec<D3D12_RESOURCE_DESC> = slice.iter().map(sanitize_resource_desc).collect();
            unsafe { (*this).device.GetResourceAllocationInfo(visible_mask, &sanitized) }
        };
        unsafe { *out = info };
    }
    out
}

unsafe extern "system" fn create_placed_resource_x(
    this: *mut XboxDeviceX,
    _gpu_va: u64,
    desc: *const D3D12_RESOURCE_DESC,
    initial_state: D3D12_RESOURCE_STATES,
    clear_value: *const D3D12_CLEAR_VALUE,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if desc.is_null() || riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    let heap_props = D3D12_HEAP_PROPERTIES {
        Type: D3D12_HEAP_TYPE_DEFAULT,
        CPUPageProperty: D3D12_CPU_PAGE_PROPERTY_UNKNOWN,
        MemoryPoolPreference: D3D12_MEMORY_POOL_UNKNOWN,
        CreationNodeMask: 1,
        VisibleNodeMask: 1,
    };
    let state = if initial_state.0 < 0 {
        D3D12_RESOURCE_STATE_COMMON
    } else {
        initial_state
    };
    let opt_clear = if clear_value.is_null() {
        None
    } else {
        Some(clear_value)
    };
    unsafe {
        let dev = &(*this).device;
        let d = sanitize_resource_desc(&*desc);
        let mut res: Option<ID3D12Resource> = None;
        match dev.CreateCommittedResource(
            &heap_props,
            D3D12_HEAP_FLAG_NONE,
            &d,
            state,
            opt_clear,
            &mut res,
        ) {
            Ok(()) => {
                *ppv = res.expect("CreateCommittedResource Ok").into_raw();
                0
            }
            Err(e) => {
                eprintln!(
                    "[GPU] CreatePlacedResourceX dim={} w={} h={} flags={:#x} layout={} align={} failed: {:?}",
                    d.Dimension.0, d.Width, d.Height, d.Flags.0, d.Layout.0, d.Alignment, e
                );
                e.code().0
            }
        }
    }
}

unsafe extern "system" fn create_committed_resource(
    this: *mut XboxDeviceX,
    heap_props: *const D3D12_HEAP_PROPERTIES,
    heap_flags: D3D12_HEAP_FLAGS,
    desc: *const D3D12_RESOURCE_DESC,
    initial_state: D3D12_RESOURCE_STATES,
    clear_value: *const D3D12_CLEAR_VALUE,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if heap_props.is_null() || desc.is_null() || riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    unsafe {
        *ppv = std::ptr::null_mut();
        let dev = &(*this).device;
        let d = sanitize_resource_desc(&*desc);
        let props = *heap_props;
        let mut state = if initial_state.0 < 0 { D3D12_RESOURCE_STATE_COMMON } else { initial_state };
        if d.Dimension != D3D12_RESOURCE_DIMENSION_BUFFER
            && (state.0 & (D3D12_RESOURCE_STATE_VERTEX_AND_CONSTANT_BUFFER.0
                | D3D12_RESOURCE_STATE_INDEX_BUFFER.0)) != 0
        {
            eprintln!("[GPU] normalized buffer-only initial state {:#x} for texture resource", state.0);
            state = D3D12_RESOURCE_STATE_COMMON;
        }
        let opt_clear = (!clear_value.is_null()).then_some(clear_value);
        let pc_heap_flags = D3D12_HEAP_FLAGS(heap_flags.0 & !D3D12_HEAP_FLAG_ALLOW_DISPLAY.0);
        let mut resource: Option<ID3D12Resource> = None;
        let mut used_desc = d;
        let mut used_clear = opt_clear;
        let mut result = dev.CreateCommittedResource(
            &props, pc_heap_flags, &used_desc, state, used_clear, &mut resource,
        );
        if result.is_err() && (used_desc.Flags.0 & D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS.0) != 0 {
            used_desc.Flags.0 &= !D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS.0;
            result = dev.CreateCommittedResource(
                &props, pc_heap_flags, &used_desc, state, used_clear, &mut resource,
            );
            if result.is_ok() {
                eprintln!("[GPU] retried committed resource without Xbox UAV flag");
            }
        }
        if result.is_err() && used_clear.is_some() {
            used_clear = None;
            result = dev.CreateCommittedResource(
                &props, pc_heap_flags, &used_desc, state, used_clear, &mut resource,
            );
            if result.is_ok() {
                eprintln!("[GPU] retried committed resource without optimized clear value");
            }
        }
        if result.is_err() && used_desc.Flags.0 != 0 {
            used_desc.Flags = D3D12_RESOURCE_FLAGS(0);
            result = dev.CreateCommittedResource(
                &props, pc_heap_flags, &used_desc, state, used_clear, &mut resource,
            );
            if result.is_ok() {
                eprintln!("[GPU] retried committed resource without Xbox resource flags");
            }
        }
        match result {
            Ok(()) => {
                let resource = resource.expect("successful committed resource creation");
                if props.Type == D3D12_HEAP_TYPE_DEFAULT
                    && let Some(&allocator) = TITLE_ALLOCATOR.get()
                {
                    let allocation = unsafe {
                        (*this).device.GetResourceAllocationInfo(0, &[d]).SizeInBytes
                    };
                    if allocation != 0 && allocation != u64::MAX {
                        type Allocate = unsafe extern "system" fn(usize, u64) -> *mut c_void;
                        let allocate: Allocate = unsafe { std::mem::transmute(allocator) };
                        let backing = unsafe { allocate(allocation as usize, 0x0080_8000) };
                        if !backing.is_null() {
                            TITLE_RESOURCE_ALLOCATIONS
                                .get_or_init(|| Mutex::new(Vec::new()))
                                .lock()
                                .map(|mut allocations| allocations.push(backing as usize))
                                .ok();
                            eprintln!("[GPU] charged {allocation:#x} bytes to title allocator at {backing:p}");
                        } else {
                            eprintln!("[GPU] title allocator rejected resource charge of {allocation:#x} bytes");
                        }
                    }
                }
                *ppv = resource.into_raw();
                eprintln!("[GPU] CreateCommittedResourceX ok dim={} size={}x{} flags={:#x}", d.Dimension.0, d.Width, d.Height, used_desc.Flags.0);
                0
            }
            Err(e) => {
                eprintln!(
                    "[GPU] CreateCommittedResource dim={} w={} h={} depth={} mips={} format={} sample=({}, {}) layout={} align={} flags={:#x} heap={} cpu_page={} pool={} nodes=({}, {}) heap_flags={:#x} state={:#x} failed: {:?}",
                    d.Dimension.0, d.Width, d.Height, d.DepthOrArraySize, d.MipLevels,
                    d.Format.0, d.SampleDesc.Count, d.SampleDesc.Quality, d.Layout.0,
                    d.Alignment, d.Flags.0, props.Type.0, props.CPUPageProperty.0,
                    props.MemoryPoolPreference.0, props.CreationNodeMask, props.VisibleNodeMask,
                    pc_heap_flags.0, state.0, e
                );
                e.code().0
            }
        }
    }
}

unsafe extern "system" fn create_committed_resource_x(
    this: *mut XboxDeviceX,
    heap_props: *const D3D12_HEAP_PROPERTIES,
    heap_flags: D3D12_HEAP_FLAGS,
    desc: *const D3D12_RESOURCE_DESC,
    initial_state: D3D12_RESOURCE_STATES,
    clear_value: *const D3D12_CLEAR_VALUE,
    _protected_session: *mut c_void,
    _castable_format_count: u32,
    _castable_formats: *const c_void,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    unsafe {
        create_committed_resource(
            this, heap_props, heap_flags, desc, initial_state, clear_value, riid, ppv,
        )
    }
}

unsafe extern "system" fn create_heap(
    this: *mut XboxDeviceX,
    desc: *const D3D12_HEAP_DESC,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if desc.is_null() || riid.is_null() || ppv.is_null() {
        return -2147467261;
    }
    unsafe {
        *ppv = std::ptr::null_mut();
        let mut d = *desc;
        // Xbox heap flags include platform-only bits; keep the PC D3D12 flags.
        d.Flags = D3D12_HEAP_FLAGS(d.Flags.0 & 0x3fff);
        let mut heap: Option<ID3D12Heap> = None;
        match (*this).device.CreateHeap(&d, &mut heap) {
            Ok(()) => {
                *ppv = heap.expect("successful heap creation").into_raw();
                0
            }
            Err(e) => {
                eprintln!("[GPU] CreateHeap size={} flags={:#x} failed: {:?}", d.SizeInBytes, d.Flags.0, e);
                e.code().0
            }
        }
    }
}

unsafe extern "system" fn stub_ok_device() -> i32 {
    0
}

unsafe extern "system" fn unimpl_slot<const SLOT: usize>(this: *mut XboxDeviceX) -> i32 {
    let ret = if this.is_null() { 0 } else { unsafe { (*this).device.GetNodeCount() as i32 } };
    eprintln!("[GPU] XboxDeviceX unimplemented slot {SLOT} (offset {:#x}) this={this:p} ret={ret}", SLOT * 8);
    ret
}

unsafe extern "system" fn device_slot_70(
    this: *mut XboxDeviceX,
    desc: *const D3D12_RESOURCE_DESC,
    out: *mut D3D12_RESOURCE_ALLOCATION_INFO,
) -> i32 {
    if this.is_null() || desc.is_null() || out.is_null() {
        return -2147467261;
    }
    unsafe {
        let desc = sanitize_resource_desc(&*desc);
        let info = (*this).device.GetResourceAllocationInfo(0, &[desc]);
        *out = info;
        eprintln!(
            "[GPU] GetResourceAllocationInfoX dim={} width={} height={} -> size={:#x} align={:#x}",
            desc.Dimension.0, desc.Width, desc.Height, info.SizeInBytes, info.Alignment
        );
        0
    }
}

macro_rules! device_vtbl_160 {
    ($($s:expr),* $(,)?) => {
        SyncVtbl([
            qi as *const c_void,                                   // 0: QueryInterface
            addref as *const c_void,                               // 1: AddRef
            release as *const c_void,                              // 2: Release
            stub_ok_device as *const c_void,                       // 3: GetPrivateData
            stub_ok_device as *const c_void,                       // 4: SetPrivateData
            stub_ok_device as *const c_void,                       // 5: SetPrivateDataInterface
            stub_ok_device as *const c_void,                       // 6: SetName
            get_node_count as *const c_void,                       // 7: GetNodeCount
            create_command_queue as *const c_void,                 // 8: CreateCommandQueue
            create_command_allocator as *const c_void,             // 9: CreateCommandAllocator
            create_graphics_pipeline_state as *const c_void,       // 10: CreateGraphicsPipelineState
            create_compute_pipeline_state as *const c_void,        // 11: CreateComputePipelineState
            create_command_list as *const c_void,                  // 12: CreateCommandList
            check_feature_support as *const c_void,                // 13: CheckFeatureSupport
            create_descriptor_heap as *const c_void,               // 14: CreateDescriptorHeap
            get_descriptor_handle_increment_size as *const c_void, // 15: GetDescriptorHandleIncrementSize
            create_root_signature as *const c_void,                // 16: CreateRootSignature
            create_constant_buffer_view as *const c_void,          // 17: CreateConstantBufferView
            create_shader_resource_view as *const c_void,          // 18: CreateShaderResourceView
            create_unordered_access_view as *const c_void,         // 19: CreateUnorderedAccessView
            create_render_target_view as *const c_void,            // 20: CreateRenderTargetView
            create_depth_stencil_view as *const c_void,            // 21: CreateDepthStencilView
            create_sampler as *const c_void,                       // 22: CreateSampler
            unimpl_slot::<23> as *const c_void,                    // 23: CopyDescriptors
            unimpl_slot::<24> as *const c_void,                    // 24: CopyDescriptorsSimple
            get_resource_allocation_info as *const c_void,         // 25: GetResourceAllocationInfo
            get_custom_heap_properties as *const c_void,           // 26: GetCustomHeapProperties
            create_committed_resource as *const c_void,            // 27: CreateCommittedResource
            create_heap as *const c_void,                          // 28: CreateHeap
            unimpl_slot::<29> as *const c_void,                    // 29: CreatePlacedResource
            unimpl_slot::<30> as *const c_void,                    // 30: CreateReservedResource
            unimpl_slot::<31> as *const c_void,                    // 31: CreateSharedHandle
            unimpl_slot::<32> as *const c_void,                    // 32: OpenSharedHandle
            unimpl_slot::<33> as *const c_void,                    // 33: OpenSharedHandleByName
            unimpl_slot::<34> as *const c_void,                    // 34: MakeResident
            unimpl_slot::<35> as *const c_void,                    // 35: Evict
            create_fence as *const c_void,                         // 36: CreateFence
            get_device_removed_reason as *const c_void,            // 37: GetDeviceRemovedReason
            unimpl_slot::<38> as *const c_void,                    // 38: GetCopyableFootprints
            unimpl_slot::<39> as *const c_void,                    // 39: CreateQueryHeap
            unimpl_slot::<40> as *const c_void,                    // 40: SetStablePowerState
            unimpl_slot::<41> as *const c_void,                    // 41: CreateCommandSignature
            unimpl_slot::<42> as *const c_void,                    // 42: GetResourceTiling
            unimpl_slot::<43> as *const c_void,                    // 43: GetAdapterLuid
            $(unimpl_slot::<$s> as *const c_void,)*
        ])
    };
}

static DEVICE_VTBL: SyncVtbl<160> = {
    let mut tbl = device_vtbl_160!(
        44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75,
        76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91,
        92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
        108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
        124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139,
        140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
        156, 157, 158, 159
    );
    tbl.0[48] = create_command_queue_x as *const c_void;
    tbl.0[62] = create_graphics_pipeline_state_x as *const c_void;
    tbl.0[70] = device_slot_70 as *const c_void;
    tbl.0[73] = create_command_list_x as *const c_void;
    tbl.0[78] = stub_ok_device as *const c_void; // SetFrameIntervalX
    tbl.0[79] = stub_ok_device as *const c_void; // ScheduleFrameEventX
    tbl.0[127] = create_committed_resource_x as *const c_void;
    tbl.0[133] = create_placed_resource_x as *const c_void;
    tbl
};

pub fn create_xbox_device_x() -> anyhow::Result<*mut XboxDeviceX> {
    let dev = init_global_device()?;
    Ok(Box::into_raw(Box::new(XboxDeviceX {
        vtable: DEVICE_VTBL.0.as_ptr(),
        ref_count: AtomicU32::new(1),
        device: dev.device.clone(),
    })))
}
