//! Native PE32+ parser, mapper, relocator, unwind/TLS setup, and import binder.

use std::collections::HashMap;
use std::ffi::CString;
use std::path::Path;

use anyhow::{Context, Result, bail};
use windows_sys::Win32::System::Diagnostics::Debug::RtlAddFunctionTable;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, VirtualAlloc, VirtualFree, VirtualProtect,
};
use windows_sys::Win32::System::Threading::TlsAlloc;

const DOS_MAGIC: u16 = 0x5A4D;
const PE_SIG: u32 = 0x0000_4550;
const OPT_MAGIC_PE64: u16 = 0x20B;
const MACHINE_AMD64: u16 = 0x8664;

const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_EXCEPTION: usize = 3;
const DIR_BASERELOC: usize = 5;
const DIR_TLS: usize = 9;
const DIR_DELAY_IMPORT: usize = 13;

const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct DataDir {
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct PeHeaders {
    pub preferred_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry_point_rva: u32,
    pub is_dll: bool,
    pub sections: Vec<SectionInfo>,
    pub dirs: Vec<DataDir>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSymbol<'a> {
    Name(&'a str),
    Ordinal(u16),
}

#[derive(Debug, Default)]
pub struct BindReport {
    pub bound_total: usize,
    pub missing: Vec<(String, String)>,
}

pub struct MappedImage {
    pub name: String,
    pub base: usize,
    pub size: usize,
    pub preferred_base: u64,
    pub entry_point: usize,
    pub tls_index: Option<u32>,
    pub tls_raw_start: usize,
    pub tls_raw_size: usize,
    pub tls_zero_fill: usize,
    pub tls_callbacks: Vec<usize>,
    pub headers: PeHeaders,
    exports: HashMap<String, usize>,
    exports_by_ord: HashMap<u16, usize>,
}

impl Drop for MappedImage {
    fn drop(&mut self) {
        if self.base != 0 {
            // SAFETY: `self.base` was allocated with `VirtualAlloc(..., MEM_RESERVE | MEM_COMMIT)`.
            unsafe { VirtualFree(self.base as *mut _, 0, MEM_RELEASE) };
        }
    }
}

fn u16_at(b: &[u8], off: usize) -> Result<u16> {
    let s: [u8; 2] = b.get(off..off + 2).context("unexpected EOF reading u16")?.try_into()?;
    Ok(u16::from_le_bytes(s))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32> {
    let s: [u8; 4] = b.get(off..off + 4).context("unexpected EOF reading u32")?.try_into()?;
    Ok(u32::from_le_bytes(s))
}

fn u64_at(b: &[u8], off: usize) -> Result<u64> {
    let s: [u8; 8] = b.get(off..off + 8).context("unexpected EOF reading u64")?.try_into()?;
    Ok(u64::from_le_bytes(s))
}

pub fn parse_headers(bytes: &[u8]) -> Result<PeHeaders> {
    if u16_at(bytes, 0)? != DOS_MAGIC {
        bail!("not a DOS MZ image");
    }
    let pe_off = u32_at(bytes, 0x3C)? as usize;
    if u32_at(bytes, pe_off)? != PE_SIG {
        bail!("invalid PE signature");
    }
    let coff = pe_off + 4;
    let machine = u16_at(bytes, coff)?;
    if machine != MACHINE_AMD64 {
        bail!("unsupported PE machine {machine:#x} (expected x86-64)");
    }
    let num_sections = u16_at(bytes, coff + 2)? as usize;
    let opt_size = u16_at(bytes, coff + 16)? as usize;
    let characteristics = u16_at(bytes, coff + 18)?;
    let opt = coff + 20;
    if u16_at(bytes, opt)? != OPT_MAGIC_PE64 {
        bail!("not a PE32+ (64-bit) image");
    }
    let entry_point_rva = u32_at(bytes, opt + 16)?;
    let preferred_base = u64_at(bytes, opt + 24)?;
    let size_of_image = u32_at(bytes, opt + 56)?;
    let size_of_headers = u32_at(bytes, opt + 60)?;
    let num_rvas = (u32_at(bytes, opt + 108)? as usize).min(16);

    let mut dirs = Vec::with_capacity(num_rvas);
    for i in 0..num_rvas {
        let off = opt + 112 + i * 8;
        dirs.push(DataDir {
            rva: u32_at(bytes, off)?,
            size: u32_at(bytes, off + 4)?,
        });
    }

    let sec_off = opt + opt_size;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sec_off + i * 40;
        let raw_name = bytes.get(s..s + 8).context("truncated section table")?;
        let end = raw_name.iter().position(|&c| c == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..end]).into_owned();
        sections.push(SectionInfo {
            name,
            virtual_size: u32_at(bytes, s + 8)?,
            virtual_address: u32_at(bytes, s + 12)?,
            raw_size: u32_at(bytes, s + 16)?,
            raw_offset: u32_at(bytes, s + 20)?,
            characteristics: u32_at(bytes, s + 36)?,
        });
    }

    Ok(PeHeaders {
        preferred_base,
        size_of_image,
        size_of_headers,
        entry_point_rva,
        is_dll: (characteristics & 0x2000) != 0,
        sections,
        dirs,
    })
}

impl MappedImage {
    pub fn load_file(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_owned());
        Self::load_bytes(&name, &bytes)
    }

    pub fn load_bytes(name: &str, bytes: &[u8]) -> Result<Self> {
        let headers = parse_headers(bytes)?;
        let size = headers.size_of_image as usize;

        // Try preferred ImageBase first, fall back to any address.
        let mut base = unsafe {
            VirtualAlloc(
                headers.preferred_base as *const _,
                size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        } as usize;
        if base == 0 {
            base = unsafe {
                VirtualAlloc(
                    std::ptr::null(),
                    size,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                )
            } as usize;
        }
        if base == 0 {
            bail!("VirtualAlloc({size:#x}) failed for {name}");
        }

        // Copy PE headers
        let hdr_copy = (headers.size_of_headers as usize).min(bytes.len()).min(size);
        // SAFETY: `base..base+size` is freshly committed RW memory.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), base as *mut u8, hdr_copy) };

        // Copy sections
        for sec in &headers.sections {
            if sec.raw_size == 0 || sec.raw_offset == 0 {
                continue;
            }
            let src_start = sec.raw_offset as usize;
            let copy_len = (sec.raw_size as usize)
                .min(bytes.len().saturating_sub(src_start))
                .min(size.saturating_sub(sec.virtual_address as usize));
            if copy_len > 0 {
                let dst = (base + sec.virtual_address as usize) as *mut u8;
                // SAFETY: `dst..dst+copy_len` is within `base..base+size`.
                unsafe { std::ptr::copy_nonoverlapping(bytes[src_start..].as_ptr(), dst, copy_len) };
            }
        }

        let mut img = Self {
            name: name.to_owned(),
            base,
            size,
            preferred_base: headers.preferred_base,
            entry_point: if headers.entry_point_rva != 0 {
                base + headers.entry_point_rva as usize
            } else {
                0
            },
            tls_index: None,
            tls_raw_start: 0,
            tls_raw_size: 0,
            tls_zero_fill: 0,
            tls_callbacks: Vec::new(),
            headers,
            exports: HashMap::new(),
            exports_by_ord: HashMap::new(),
        };

        img.apply_relocations()?;
        img.setup_tls()?;
        img.parse_exports()?;
        img.register_pdata();
        img.protect_sections()?;

        tracing::info!(
            name = %img.name,
            base = format_args!("{:#x}", img.base),
            preferred = format_args!("{:#x}", img.preferred_base),
            size_mb = img.size >> 20,
            "mapped PE32+ image"
        );
        Ok(img)
    }

    fn slice(&self, rva: u32, len: usize) -> Option<&[u8]> {
        let start = rva as usize;
        if start.checked_add(len)? > self.size {
            return None;
        }
        // SAFETY: `self.base..self.base+self.size` is committed for the lifetime of `self`.
        Some(unsafe { std::slice::from_raw_parts((self.base + start) as *const u8, len) })
    }

    fn read_cstr(&self, rva: u32) -> Option<String> {
        let start = rva as usize;
        if start >= self.size {
            return None;
        }
        let max_len = (self.size - start).min(512);
        let s = self.slice(rva, max_len)?;
        let nul = s.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&s[..nul]).into_owned())
    }

    fn apply_relocations(&self) -> Result<()> {
        let delta = (self.base as i64).wrapping_sub(self.preferred_base as i64);
        if delta == 0 {
            return Ok(());
        }
        let Some(dir) = self.headers.dirs.get(DIR_BASERELOC).copied() else {
            return Ok(());
        };
        if dir.rva == 0 || dir.size == 0 {
            return Ok(());
        }
        let mut off = 0usize;
        let block = self.slice(dir.rva, dir.size as usize).context("reloc dir out of range")?.to_vec();
        while off + 8 <= block.len() {
            let page_rva = u32_at(&block, off)?;
            let block_size = u32_at(&block, off + 4)? as usize;
            if block_size < 8 || off + block_size > block.len() {
                break;
            }
            let count = (block_size - 8) / 2;
            for i in 0..count {
                let entry = u16_at(&block, off + 8 + i * 2)?;
                let ty = entry >> 12;
                let rva = page_rva as usize + (entry & 0x0FFF) as usize;
                if ty == 10 && rva + 8 <= self.size {
                    let ptr = (self.base + rva) as *mut u64;
                    // SAFETY: within mapped RW image.
                    unsafe {
                        let v = ptr.read_unaligned();
                        ptr.write_unaligned((v as i64).wrapping_add(delta) as u64);
                    }
                } else if ty == 3 && rva + 4 <= self.size {
                    let ptr = (self.base + rva) as *mut u32;
                    // SAFETY: within mapped RW image.
                    unsafe {
                        let v = ptr.read_unaligned();
                        ptr.write_unaligned((v as i32).wrapping_add(delta as i32) as u32);
                    }
                }
            }
            off += block_size;
        }
        Ok(())
    }

    fn setup_tls(&mut self) -> Result<()> {
        let Some(dir) = self.headers.dirs.get(DIR_TLS).copied() else {
            return Ok(());
        };
        if dir.rva == 0 || dir.size < 40 {
            return Ok(());
        }
        let tls = self.slice(dir.rva, 40).context("TLS dir out of range")?.to_vec();
        let raw_start = u64_at(&tls, 0)? as usize;
        let raw_end = u64_at(&tls, 8)? as usize;
        let addr_of_index = u64_at(&tls, 16)? as usize;
        let addr_of_callbacks = u64_at(&tls, 24)? as usize;
        let zero_fill = u32_at(&tls, 32)? as usize;

        if raw_end >= raw_start && raw_start >= self.base && raw_end <= self.base + self.size {
            self.tls_raw_start = raw_start;
            self.tls_raw_size = raw_end - raw_start;
            self.tls_zero_fill = zero_fill;
        }

        // Use slot 0 for the main executable (matching LTCG fast-path assumptions)
        // and slot 0/existing ntdll array without replacing ntdll's `gs:[0x58]` pointer.
        let idx = 0u32;
        if addr_of_index >= self.base && addr_of_index + 4 <= self.base + self.size {
            // SAFETY: `AddressOfIndex` lies inside mapped `.data`/`.rdata`.
            unsafe { (addr_of_index as *mut u32).write_unaligned(idx) };
        }
        self.tls_index = Some(idx);
        let _ = TlsAlloc;

        if addr_of_callbacks >= self.base && addr_of_callbacks + 8 <= self.base + self.size {
            let mut p = addr_of_callbacks;
            while p + 8 <= self.base + self.size {
                // SAFETY: reading null-terminated callback pointer array in mapped image.
                let cb = unsafe { (p as *const usize).read_unaligned() };
                if cb == 0 {
                    break;
                }
                self.tls_callbacks.push(cb);
                p += 8;
            }
        }
        Ok(())
    }

    fn parse_exports(&mut self) -> Result<()> {
        let Some(dir) = self.headers.dirs.get(DIR_EXPORT).copied() else {
            return Ok(());
        };
        if dir.rva == 0 || dir.size < 40 {
            return Ok(());
        }
        let exp = self.slice(dir.rva, 40).context("export dir out of range")?.to_vec();
        let ord_base = u32_at(&exp, 16)? as u16;
        let num_funcs = u32_at(&exp, 20)? as usize;
        let num_names = u32_at(&exp, 24)? as usize;
        let funcs_rva = u32_at(&exp, 28)?;
        let names_rva = u32_at(&exp, 32)?;
        let ords_rva = u32_at(&exp, 36)?;

        let Some(funcs) = self.slice(funcs_rva, num_funcs * 4).map(|s| s.to_vec()) else {
            return Ok(());
        };
        for i in 0..num_funcs {
            let fn_rva = u32_at(&funcs, i * 4)?;
            if fn_rva != 0 {
                self.exports_by_ord.insert(ord_base.wrapping_add(i as u16), self.base + fn_rva as usize);
            }
        }
        if let (Some(names), Some(ords)) = (
            self.slice(names_rva, num_names * 4).map(|s| s.to_vec()),
            self.slice(ords_rva, num_names * 2).map(|s| s.to_vec()),
        ) {
            for i in 0..num_names {
                let name_rva = u32_at(&names, i * 4)?;
                let ord_idx = u16_at(&ords, i * 2)? as usize;
                if let Some(sym) = self.read_cstr(name_rva)
                    && let Some(fn_rva) = funcs.get(ord_idx * 4..ord_idx * 4 + 4).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes)
                    && fn_rva != 0
                {
                    self.exports.insert(sym, self.base + fn_rva as usize);
                }
            }
        }
        Ok(())
    }

    fn register_pdata(&self) {
        let Some(dir) = self.headers.dirs.get(DIR_EXCEPTION).copied() else {
            return;
        };
        if dir.rva == 0 || dir.size < 12 {
            return;
        }
        let count = dir.size / 12;
        let table = (self.base + dir.rva as usize) as *mut _;
        // SAFETY: `.pdata` contains `count` `RUNTIME_FUNCTION` entries valid for `self`'s lifetime.
        unsafe { RtlAddFunctionTable(table, count, self.base as u64) };
    }

    fn protect_sections(&self) -> Result<()> {
        for sec in &self.headers.sections {
            let len = (sec.virtual_size.max(sec.raw_size) as usize)
                .min(self.size.saturating_sub(sec.virtual_address as usize));
            if len == 0 {
                continue;
            }
            let prot = match (
                (sec.characteristics & SCN_MEM_EXECUTE) != 0,
                (sec.characteristics & SCN_MEM_READ) != 0,
                (sec.characteristics & SCN_MEM_WRITE) != 0,
            ) {
                (true, true, true) => PAGE_EXECUTE_READWRITE,
                (true, true, false) => PAGE_EXECUTE_READ,
                (true, false, false) => PAGE_EXECUTE,
                (false, true, true) => PAGE_READWRITE,
                (false, true, false) => PAGE_READONLY,
                (false, false, false) => PAGE_NOACCESS,
                _ => PAGE_READWRITE,
            };
            let mut old = 0u32;
            // SAFETY: range is inside our committed image allocation.
            unsafe {
                VirtualProtect((self.base + sec.virtual_address as usize) as *const _, len, prot, &mut old);
            }
        }
        Ok(())
    }

    pub fn export(&self, sym: &ImportSymbol<'_>) -> Option<usize> {
        match sym {
            ImportSymbol::Name(n) => self.exports.get(*n).copied(),
            ImportSymbol::Ordinal(o) => self.exports_by_ord.get(o).copied(),
        }
    }

    /// Initializes the current thread's `TEB->ThreadLocalStoragePointer[0]`
    /// slot with a fresh copy of this module's `.tls` template without replacing
    /// `ntdll`'s `gs:[0x58]` heap allocation.
    pub unsafe fn init_thread_tls(&self, bind_slot_zero: bool) -> *mut u8 {
        if !bind_slot_zero {
            return std::ptr::null_mut();
        }
        let total = (self.tls_raw_size + self.tls_zero_fill).max(64);
        let block = vec![0u8; total].into_boxed_slice();
        let block_ptr = Box::into_raw(block).cast::<u8>();
        if self.tls_raw_size > 0 && self.tls_raw_start != 0 {
            // SAFETY: `tls_raw_start..+tls_raw_size` lies inside mapped `.tls` and `block_ptr` has `total` bytes.
            unsafe { std::ptr::copy_nonoverlapping(self.tls_raw_start as *const u8, block_ptr, self.tls_raw_size) };
        }
        // SAFETY: reading `gs:[0x58]` (TEB->ThreadLocalStoragePointer) on x86_64 Windows.
        let tls_array: *mut *mut u8;
        unsafe {
            std::arch::asm!("mov {}, gs:[0x58]", out(reg) tls_array, options(nostack, readonly));
        }
        if !tls_array.is_null() {
            // SAFETY: slot 0 exists in `ntdll`'s `gs:[0x58]` for `scarlett.exe`.
            unsafe { *tls_array = block_ptr };
        }
        block_ptr
    }

    /// Walks the PE import directory and patches the IAT with resolved addresses.
    pub fn bind_imports<F>(&self, mut resolve: F) -> Result<BindReport>
    where
        F: FnMut(&str, &ImportSymbol<'_>) -> Option<usize>,
    {
        let mut report = BindReport::default();
        let Some(dir) = self.headers.dirs.get(DIR_IMPORT).copied() else {
            return Ok(report);
        };
        if dir.rva == 0 || dir.size < 20 {
            return Ok(report);
        }

        let mut desc_rva = dir.rva;
        loop {
            let Some(desc) = self.slice(desc_rva, 20).map(|s| s.to_vec()) else {
                break;
            };
            let ilt_rva = u32_at(&desc, 0)?;
            let name_rva = u32_at(&desc, 12)?;
            let iat_rva = u32_at(&desc, 16)?;
            if name_rva == 0 && ilt_rva == 0 {
                break;
            }
            let dll = self.read_cstr(name_rva).unwrap_or_default();
            let lookup_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };

            let mut idx = 0u32;
            loop {
                let entry_rva = lookup_rva + idx * 8;
                let slot_rva = iat_rva + idx * 8;
                let Some(entry_bytes) = self.slice(entry_rva, 8) else {
                    break;
                };
                let entry = u64_at(entry_bytes, 0)?;
                if entry == 0 {
                    break;
                }
                let sym_name;
                let sym = if (entry & (1u64 << 63)) != 0 {
                    ImportSymbol::Ordinal((entry & 0xFFFF) as u16)
                } else {
                    let hint_name_rva = (entry & 0x7FFF_FFFF) as u32;
                    sym_name = self.read_cstr(hint_name_rva + 2).unwrap_or_default();
                    ImportSymbol::Name(sym_name.as_str())
                };

                if let Some(addr) = resolve(&dll, &sym) {
                    let iat_ptr = (self.base + slot_rva as usize) as *mut usize;
                    let mut old = 0u32;
                    // SAFETY: temporarily ensure IAT page is writable while patching, then restore.
                    unsafe {
                        VirtualProtect(iat_ptr as *const _, 8, PAGE_READWRITE, &mut old);
                        iat_ptr.write_unaligned(addr);
                        VirtualProtect(iat_ptr as *const _, 8, old, &mut old);
                    }
                    report.bound_total += 1;
                } else {
                    report.missing.push((dll.clone(), format!("{sym:?}")));
                }
                idx += 1;
            }
            desc_rva += 20;
        }

        let _ = CString::new("");
        let _ = DIR_DELAY_IMPORT;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_game_binary_headers_if_present() {
        let p = Path::new(r"E:\GTA 6\GTA6.Xbox.v1.0.2.1-CYBERLEEK\game_scarlett_master.exe");
        if !p.exists() {
            return;
        }
        let f = std::fs::read(p).unwrap();
        let h = parse_headers(&f).unwrap();
        assert_eq!(h.preferred_base, 0x14000_0000);
        assert!(h.sections.len() >= 10);
    }
}
