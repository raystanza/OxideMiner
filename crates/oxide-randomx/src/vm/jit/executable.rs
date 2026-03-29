//! Platform-specific executable buffer for JIT code.

use crate::errors::{RandomXError, Result};
#[cfg(windows)]
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};

/// RW/RX executable buffer used by the JIT backend.
pub struct ExecutableBuffer {
    ptr: NonNull<u8>,
    len: usize,
    alloc_len: usize,
    state: BufferState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BufferState {
    ReadWrite,
    ReadExec,
}

// Executable buffers are immutable after finalize_rx and can be shared safely.
unsafe impl Send for ExecutableBuffer {}
unsafe impl Sync for ExecutableBuffer {}

impl ExecutableBuffer {
    /// Allocate a new executable buffer of `len` bytes.
    pub fn new(len: usize) -> Result<Self> {
        if len == 0 {
            return Err(RandomXError::InvalidArgument(
                "jit executable buffer length is zero",
            ));
        }
        let alloc_len = round_up_to_page(len);
        let ptr = unsafe { alloc_rw(alloc_len)? };
        Ok(Self {
            ptr,
            len,
            alloc_len,
            state: BufferState::ReadWrite,
        })
    }

    /// Write raw bytes into the buffer (only valid before `finalize_rx`).
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if self.state != BufferState::ReadWrite {
            return Err(RandomXError::InvalidArgument(
                "jit executable buffer is not writable",
            ));
        }
        if bytes.len() > self.len {
            return Err(RandomXError::InvalidArgument(
                "jit executable buffer overflow",
            ));
        }
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.as_ptr(), bytes.len());
        }
        Ok(())
    }

    /// Mark the buffer read/execute and revoke write access.
    pub fn finalize_rx(&mut self) -> Result<()> {
        if self.state == BufferState::ReadExec {
            return Err(RandomXError::InvalidArgument(
                "jit executable buffer already executable",
            ));
        }
        unsafe { protect_rx(self.ptr.as_ptr(), self.alloc_len)? };
        self.state = BufferState::ReadExec;
        Ok(())
    }

    /// # Safety
    /// The caller must ensure the buffer contains a valid function body for `T` and that
    /// `finalize_rx` has been called before execution.
    pub unsafe fn as_fn_ptr<T>(&self) -> T
    where
        T: Copy,
    {
        debug_assert_eq!(core::mem::size_of::<T>(), core::mem::size_of::<*const ()>());
        let ptr = self.ptr.as_ptr() as *const ();
        let raw = &ptr as *const *const ();
        let func = raw.cast::<T>();
        unsafe { func.read_unaligned() }
    }

    /// Returns true if the buffer is read/execute (finalized).
    pub fn is_rx(&self) -> bool {
        self.state == BufferState::ReadExec
    }
}

impl Drop for ExecutableBuffer {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr(), self.alloc_len);
        }
    }
}

fn round_up_to_page(value: usize) -> usize {
    let page = page_size();
    (value + page - 1) & !(page - 1)
}

#[cfg(windows)]
fn page_size() -> usize {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    unsafe {
        let mut info = MaybeUninit::<SYSTEM_INFO>::zeroed();
        GetSystemInfo(info.as_mut_ptr());
        info.assume_init().dwPageSize as usize
    }
}

#[cfg(unix)]
fn page_size() -> usize {
    unsafe {
        let size = libc::sysconf(libc::_SC_PAGESIZE);
        if size <= 0 {
            4096
        } else {
            size as usize
        }
    }
}

#[cfg(windows)]
unsafe fn alloc_rw(size: usize) -> Result<NonNull<u8>> {
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    };
    let ptr = unsafe {
        VirtualAlloc(
            ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    let nn = NonNull::new(ptr as *mut u8)
        .ok_or(RandomXError::AllocationFailed("jit executable buffer"))?;
    Ok(nn)
}

#[cfg(unix)]
unsafe fn alloc_rw(size: usize) -> Result<NonNull<u8>> {
    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(RandomXError::AllocationFailed("jit executable buffer"));
    }
    NonNull::new(ptr as *mut u8).ok_or(RandomXError::AllocationFailed("jit executable buffer"))
}

#[cfg(windows)]
unsafe fn protect_rx(ptr: *mut u8, size: usize) -> Result<()> {
    use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READ};
    let mut old = 0u32;
    let ok = unsafe { VirtualProtect(ptr as *mut _, size, PAGE_EXECUTE_READ, &mut old) };
    if ok == 0 {
        return Err(RandomXError::AllocationFailed("jit protect rx"));
    }
    Ok(())
}

#[cfg(unix)]
unsafe fn protect_rx(ptr: *mut u8, size: usize) -> Result<()> {
    let res = unsafe { libc::mprotect(ptr as *mut _, size, libc::PROT_READ | libc::PROT_EXEC) };
    if res != 0 {
        return Err(RandomXError::AllocationFailed("jit protect rx"));
    }
    Ok(())
}

#[cfg(windows)]
unsafe fn dealloc(ptr: *mut u8, _size: usize) {
    use windows_sys::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
    let _ = unsafe { VirtualFree(ptr as *mut _, 0, MEM_RELEASE) };
}

#[cfg(unix)]
unsafe fn dealloc(ptr: *mut u8, size: usize) {
    let _ = unsafe { libc::munmap(ptr as *mut _, size) };
}
