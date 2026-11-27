//! Synchronous Xbox DirectStorage compatibility layer.

use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Mutex;

#[repr(transparent)]
struct SyncVtbl<const N: usize>([*const c_void; N]);
unsafe impl<const N: usize> Sync for SyncVtbl<N> {}

#[repr(C)]
struct Factory {
    vtable: *const *const c_void,
    refs: AtomicU32,
}

#[repr(C)]
struct StorageFile {
    vtable: *const *const c_void,
    refs: AtomicU32,
    file: Mutex<File>,
    path: PathBuf,
}

#[repr(C)]
struct StatusArray {
    vtable: *const *const c_void,
    refs: AtomicU32,
    complete: Vec<AtomicI32>,
    results: Vec<AtomicI32>,
}

#[derive(Clone, Copy)]
struct Request {
    options: u64,
    destination: *mut u8,
    destination_size: usize,
    file: *mut StorageFile,
    offset: u64,
    source_size: usize,
}
unsafe impl Send for Request {}

#[repr(C)]
struct Queue {
    vtable: *const *const c_void,
    refs: AtomicU32,
    requests: Mutex<Vec<Request>>,
}

unsafe extern "system" fn query_interface<T>(this: *mut T, _iid: *const c_void, out: *mut *mut c_void) -> i32 {
    if out.is_null() { return -2147467261; }
    unsafe { *out = this.cast(); }
    0
}

unsafe extern "system" fn add_ref<T>(this: *mut T) -> u32 {
    let refs = unsafe { &*(this.cast::<AtomicU32>().add(1)) };
    refs.fetch_add(1, Ordering::Relaxed) + 1
}

unsafe extern "system" fn release_factory(this: *mut Factory) -> u32 {
    unsafe { release_obj(this) }
}
unsafe extern "system" fn release_file(this: *mut StorageFile) -> u32 {
    unsafe { release_obj(this) }
}
unsafe extern "system" fn release_status(this: *mut StatusArray) -> u32 {
    unsafe { release_obj(this) }
}
unsafe extern "system" fn release_queue(this: *mut Queue) -> u32 {
    unsafe { release_obj(this) }
}

unsafe fn release_obj<T>(this: *mut T) -> u32 {
    let refs = unsafe { &*(this.cast::<AtomicU32>().add(1)) };
    let old = refs.fetch_sub(1, Ordering::AcqRel);
    if old == 1 { unsafe { drop(Box::from_raw(this)); } }
    old.saturating_sub(1)
}

fn translate_storage_path(raw: &str) -> PathBuf {
    let normalized = raw.replace('/', "\\");
    let rest = if normalized.len() >= 3
        && normalized.as_bytes()[1] == b':'
        && normalized.as_bytes()[2] == b'\\'
    {
        &normalized[3..]
    } else {
        normalized.as_str()
    };
    let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    root.join(rest.replace('\\', std::path::MAIN_SEPARATOR_STR))
}

unsafe extern "system" fn open_file(
    _this: *mut Factory,
    path: *const u16,
    _iid: *const c_void,
    out: *mut *mut c_void,
) -> i32 {
    if path.is_null() || out.is_null() { return -2147467261; }
    unsafe { *out = std::ptr::null_mut(); }
    let mut len = 0;
    while len < 4096 && unsafe { *path.add(len) } != 0 { len += 1; }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(path, len) });
    let host_path = translate_storage_path(&value);
    match File::open(&host_path) {
        Ok(file) => {
            let object = Box::new(StorageFile {
                vtable: FILE_VTBL.0.as_ptr(),
                refs: AtomicU32::new(1),
                file: Mutex::new(file),
                path: host_path.clone(),
            });
            unsafe { *out = Box::into_raw(object).cast(); }
            eprintln!("[DStorage] opened {}", host_path.display());
            0
        }
        Err(error) => {
            eprintln!("[DStorage] open failed {}: {error}", host_path.display());
            -2147024894 // HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
        }
    }
}

unsafe extern "system" fn create_status_array(
    _this: *mut Factory,
    capacity: u32,
    _name: *const u16,
    _iid: *const c_void,
    out: *mut *mut c_void,
) -> i32 {
    if out.is_null() { return -2147467261; }
    unsafe { *out = std::ptr::null_mut(); }
    let count = (capacity as usize).min(1_000_000);
    let object = Box::new(StatusArray {
        vtable: STATUS_VTBL.0.as_ptr(),
        refs: AtomicU32::new(1),
        complete: (0..count).map(|_| AtomicI32::new(0)).collect(),
        results: (0..count).map(|_| AtomicI32::new(0)).collect(),
    });
    unsafe { *out = Box::into_raw(object).cast(); }
    0
}

unsafe extern "system" fn set_staging_buffer_size(_this: *mut Factory, _size: u64) -> i32 { 0 }

unsafe extern "system" fn create_queue(
    _this: *mut Factory,
    _desc: *const c_void,
    _iid: *const c_void,
    out: *mut *mut c_void,
    _reserved: *mut c_void,
) -> i32 {
    if out.is_null() { return -2147467261; }
    let object = Box::new(Queue {
        vtable: QUEUE_VTBL.0.as_ptr(),
        refs: AtomicU32::new(1),
        requests: Mutex::new(Vec::new()),
    });
    unsafe { *out = Box::into_raw(object).cast(); }
    eprintln!("[DStorage] created queue");
    0
}

unsafe extern "system" fn enqueue_request(this: *mut Queue, request: *const u8) {
    if this.is_null() || request.is_null() { return; }
    unsafe {
        let read_u32 = |offset: usize| std::ptr::read_unaligned(request.add(offset).cast::<u32>()) as usize;
        let read_u64 = |offset: usize| std::ptr::read_unaligned(request.add(offset).cast::<u64>());
        let item = Request {
            options: read_u64(0),
            destination: read_u64(8) as *mut u8,
            destination_size: read_u32(0x18),
            file: read_u64(0x20) as *mut StorageFile,
            offset: read_u64(0x28),
            source_size: read_u32(0x30),
        };
        if let Ok(mut requests) = (*this).requests.lock() { requests.push(item); }
    }
}

unsafe extern "system" fn enqueue_status(
    _this: *mut Queue,
    _status: *mut StatusArray,
    _index: u32,
    _value: u64,
) {}

unsafe extern "system" fn enqueue_signal(_this: *mut Queue, _fence: *mut c_void, _value: u64) {}

unsafe extern "system" fn submit(this: *mut Queue) {
    if this.is_null() { return; }
    let pending = unsafe { &(*this).requests };
    let Ok(mut requests) = pending.lock() else { return; };
    let batch = std::mem::take(&mut *requests);
    drop(requests);
    for request in batch {
        if request.file.is_null() || request.destination.is_null() { continue; }
        let mut data = vec![0u8; request.source_size.min(256 * 1024 * 1024)];
        let file = unsafe { &*request.file };
        let read_result = file.file.lock().ok().and_then(|mut file| {
            file.seek(SeekFrom::Start(request.offset)).ok()?;
            file.read_exact(&mut data).ok()?;
            Some(())
        });
        if read_result.is_none() {
            eprintln!("[DStorage] read failed {} offset={:#x} bytes={:#x}", file.path.display(), request.offset, request.source_size);
            continue;
        }
        let copy_size = data.len().min(request.destination_size);
        // Raw requests can be copied directly. Compression options are diagnosed
        // explicitly until a matching decoder is available.
        if request.options & 0xff == 0 {
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), request.destination, copy_size); }
        } else {
            eprintln!("[DStorage] unsupported compression option {:#x} for {}", request.options & 0xff, file.path.display());
        }
    }
}

unsafe extern "system" fn is_complete(_this: *mut StatusArray, _index: u32) -> i32 { 1 }
unsafe extern "system" fn get_result(_this: *mut StatusArray, _index: u32) -> i32 { 0 }
unsafe extern "system" fn stub_ok() -> i32 { 0 }

static FACTORY_VTBL: SyncVtbl<12> = SyncVtbl([
    query_interface::<Factory> as *const c_void,
    add_ref::<Factory> as *const c_void,
    release_factory as *const c_void,
    stub_ok as *const c_void,
    open_file as *const c_void,
    create_status_array as *const c_void,
    stub_ok as *const c_void,
    stub_ok as *const c_void,
    set_staging_buffer_size as *const c_void,
    stub_ok as *const c_void,
    create_queue as *const c_void,
    stub_ok as *const c_void,
]);

static FILE_VTBL: SyncVtbl<8> = SyncVtbl([
    query_interface::<StorageFile> as *const c_void,
    add_ref::<StorageFile> as *const c_void,
    release_file as *const c_void,
    stub_ok as *const c_void,
    stub_ok as *const c_void,
    stub_ok as *const c_void,
    stub_ok as *const c_void,
    stub_ok as *const c_void,
]);

static STATUS_VTBL: SyncVtbl<8> = SyncVtbl([
    query_interface::<StatusArray> as *const c_void,
    add_ref::<StatusArray> as *const c_void,
    release_status as *const c_void,
    is_complete as *const c_void,
    get_result as *const c_void,
    stub_ok as *const c_void,
    stub_ok as *const c_void,
    stub_ok as *const c_void,
]);

static QUEUE_VTBL: SyncVtbl<8> = SyncVtbl([
    query_interface::<Queue> as *const c_void,
    add_ref::<Queue> as *const c_void,
    release_queue as *const c_void,
    enqueue_request as *const c_void,
    enqueue_status as *const c_void,
    enqueue_signal as *const c_void,
    submit as *const c_void,
    stub_ok as *const c_void,
]);

#[unsafe(no_mangle)]
pub unsafe extern "system" fn dstorage_get_factory(_iid: *const c_void, out: *mut *mut c_void) -> i32 {
    if out.is_null() { return -2147467261; }
    let object = Box::new(Factory { vtable: FACTORY_VTBL.0.as_ptr(), refs: AtomicU32::new(1) });
    unsafe { *out = Box::into_raw(object).cast(); }
    0
}

pub fn resolve(name: &str) -> Option<usize> {
    match name {
        "DStorageGetFactory" => Some(dstorage_get_factory as *const () as usize),
        _ => None,
    }
}
