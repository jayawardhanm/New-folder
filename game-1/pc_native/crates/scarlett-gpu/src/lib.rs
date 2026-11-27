//! PC-native Direct3D 12 backend for Scarlett titles.
//!
//! Built without UMA shared-memory emulation:
//! - Explicit `D3D12_HEAP_TYPE_DEFAULT` VRAM heaps for GPU resources & render targets.
//! - Lock-free ring-buffered `UPLOAD` heaps for CPU-written frame constants.
//! - Dedicated `COPY` queue + GPU compute-shader texture detiling.
//! - Zero global `PAGE_GUARD` / `GetWriteWatch` shadow diffing.
//! - Zero GPU->CPU readbacks for GPU-only buffers.

pub mod cmd_list_x;
pub mod device_x;
pub mod heap;
pub mod xg;
pub mod xs_entry;

use anyhow::{Context, Result};
use windows::Win32::Graphics::Direct3D::D3D_FEATURE_LEVEL_12_1;
use windows::Win32::Graphics::Direct3D12::{
    D3D12_COMMAND_LIST_TYPE_COMPUTE, D3D12_COMMAND_LIST_TYPE_COPY, D3D12_COMMAND_LIST_TYPE_DIRECT,
    D3D12_COMMAND_QUEUE_DESC, D3D12CreateDevice, ID3D12CommandQueue, ID3D12Device8,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory2, DXGI_CREATE_FACTORY_FLAGS, DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE,
    IDXGIAdapter1, IDXGIFactory6,
};

pub struct NativeDevice {
    pub factory: IDXGIFactory6,
    pub adapter: IDXGIAdapter1,
    pub device: ID3D12Device8,
    pub direct_queue: ID3D12CommandQueue,
    pub compute_queue: ID3D12CommandQueue,
    pub copy_queue: ID3D12CommandQueue,
}

impl NativeDevice {
    /// Initializes a PC-native D3D12 device with dedicated Direct, Compute, and Copy queues.
    pub fn create_high_performance() -> Result<Self> {
        // SAFETY: standard DXGI factory creation.
        let factory: IDXGIFactory6 =
            unsafe { CreateDXGIFactory2(DXGI_CREATE_FACTORY_FLAGS(0)) }.context("CreateDXGIFactory2")?;
        // SAFETY: enumerating the primary high-performance adapter.
        let adapter: IDXGIAdapter1 = unsafe {
            factory.EnumAdapterByGpuPreference(0, DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE)
        }
        .context("EnumAdapterByGpuPreference")?;

        let mut device: Option<ID3D12Device8> = None;
        // SAFETY: creating D3D12 device on the selected adapter.
        unsafe { D3D12CreateDevice(&adapter, D3D_FEATURE_LEVEL_12_1, &mut device) }
            .context("D3D12CreateDevice(12_1)")?;
        let device = device.context("D3D12CreateDevice returned null")?;

        let make_queue = |ty| -> Result<ID3D12CommandQueue> {
            let desc = D3D12_COMMAND_QUEUE_DESC {
                Type: ty,
                ..Default::default()
            };
            // SAFETY: valid queue description on live device.
            unsafe { device.CreateCommandQueue(&desc) }.context("CreateCommandQueue")
        };

        let direct_queue = make_queue(D3D12_COMMAND_LIST_TYPE_DIRECT)?;
        let compute_queue = make_queue(D3D12_COMMAND_LIST_TYPE_COMPUTE)?;
        let copy_queue = make_queue(D3D12_COMMAND_LIST_TYPE_COPY)?;

        tracing::info!("initialized PC-native D3D12Device8 (Direct + Compute + Copy queues)");
        Ok(Self {
            factory,
            adapter,
            device,
            direct_queue,
            compute_queue,
            copy_queue,
        })
    }
}
