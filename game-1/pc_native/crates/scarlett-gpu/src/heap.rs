//! PC-native VRAM (`DEFAULT`) and lock-free ring (`UPLOAD`) allocators.
//!
//! No UMA shadow copies, no `PAGE_GUARD` write-watching, and no GPU->CPU
//! readbacks for GPU-only buffers.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use windows::Win32::Graphics::Direct3D12::*;

/// Persistent CPU-mapped lock-free ring buffer in `D3D12_HEAP_TYPE_UPLOAD`.
pub struct UploadRing {
    pub resource: ID3D12Resource,
    pub cpu_base: *mut u8,
    pub gpu_base: u64,
    pub capacity: u64,
    cursor: AtomicU64,
}

// SAFETY: `ID3D12Resource` is free-threaded and `cpu_base` is a persistently mapped upload buffer.
unsafe impl Send for UploadRing {}
// SAFETY: `cursor` uses atomic fetch_add; each caller owns its disjoint slice.
unsafe impl Sync for UploadRing {}

impl UploadRing {
    pub fn new(device: &ID3D12Device8, capacity_bytes: u64) -> Result<Self> {
        let heap = D3D12_HEAP_PROPERTIES {
            Type: D3D12_HEAP_TYPE_UPLOAD,
            ..Default::default()
        };
        let desc = D3D12_RESOURCE_DESC {
            Dimension: D3D12_RESOURCE_DIMENSION_BUFFER,
            Alignment: 0,
            Width: capacity_bytes,
            Height: 1,
            DepthOrArraySize: 1,
            MipLevels: 1,
            Format: windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_UNKNOWN,
            SampleDesc: windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Layout: D3D12_TEXTURE_LAYOUT_ROW_MAJOR,
            Flags: D3D12_RESOURCE_FLAG_NONE,
        };

        let mut res: Option<ID3D12Resource> = None;
        // SAFETY: valid heap properties and buffer description on live device.
        unsafe {
            device.CreateCommittedResource(
                &heap,
                D3D12_HEAP_FLAG_NONE,
                &desc,
                D3D12_RESOURCE_STATE_GENERIC_READ,
                None,
                &mut res,
            )
        }
        .context("CreateCommittedResource(UploadRing)")?;
        let resource = res.context("UploadRing returned null")?;

        let mut mapped = std::ptr::null_mut();
        // SAFETY: `UploadRing` is upload heap; mapping the whole buffer persistently is standard D3D12.
        unsafe { resource.Map(0, None, Some(&mut mapped)) }.context("Map(UploadRing)")?;
        // SAFETY: live buffer resource.
        let gpu_base = unsafe { resource.GetGPUVirtualAddress() };

        Ok(Self {
            resource,
            cpu_base: mapped.cast(),
            gpu_base,
            capacity: capacity_bytes,
            cursor: AtomicU64::new(0),
        })
    }

    /// Lock-free 256-byte-aligned allocation from the upload ring.
    pub fn alloc(&self, size: u64) -> (*mut u8, u64, u64) {
        let aligned = (size.max(256) + 255) & !255;
        let off = self.cursor.fetch_add(aligned, Ordering::Relaxed) % self.capacity;
        let off = if off + aligned > self.capacity { 0 } else { off };
        // SAFETY: `off + aligned <= self.capacity`.
        let cpu = unsafe { self.cpu_base.add(off as usize) };
        (cpu, self.gpu_base + off, off)
    }
}
