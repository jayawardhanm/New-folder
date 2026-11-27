//! RDNA2-to-DXIL PC-native shader compiler.
//!
//! Targets native D3D12 Wave32, PC root signatures, and SM6.6 dynamic
//! descriptor indexing with a persistent versioned on-disk cache.

use std::path::PathBuf;

pub struct ShaderCache {
    pub dir: PathBuf,
}

impl ShaderCache {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}
