//! Large-page utilities and aligned buffer allocation.

use crate::errors::{RandomXError, Result};
use core::ptr::NonNull;
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::sync::Once;

type StdResult<T> = core::result::Result<T, String>;

/// Detailed huge page status for diagnostics.
/// Snapshot of huge-page availability (Linux) for diagnostics.
#[derive(Clone, Debug)]
pub struct HugePageStatus {
    /// Number of 1GB pages configured in the system.
    pub configured_1g: usize,
    /// Number of 1GB pages currently free.
    pub free_1g: usize,
    /// Number of 2MB pages configured in the system.
    pub configured_2m: usize,
    /// Number of 2MB pages currently free.
    pub free_2m: usize,
    /// Whether 1GB hugepagesz is in kernel boot parameters.
    pub kernel_1g_configured: bool,
}

impl HugePageStatus {
    /// Get the current huge page status.
    #[must_use]
    pub fn get() -> Self {
        #[cfg(target_os = "linux")]
        {
            #[cfg(miri)]
            {
                Self {
                    configured_1g: 0,
                    free_1g: 0,
                    configured_2m: 0,
                    free_2m: 0,
                    kernel_1g_configured: false,
                }
            }
            #[cfg(not(miri))]
            {
                Self {
                    configured_1g: linux_read_sysfs_usize(
                        "/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages",
                    ),
                    free_1g: linux_read_sysfs_usize(
                        "/sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages",
                    ),
                    configured_2m: linux_read_sysfs_usize(
                        "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages",
                    ),
                    free_2m: linux_read_sysfs_usize(
                        "/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages",
                    ),
                    kernel_1g_configured: linux_1g_kernel_configured(),
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self {
                configured_1g: 0,
                free_1g: 0,
                configured_2m: 0,
                free_2m: 0,
                kernel_1g_configured: false,
            }
        }
    }

    /// Check if 1GB pages are available for allocation.
    #[must_use]
    pub fn has_1g_pages(&self) -> bool {
        self.free_1g > 0
    }

    /// Check if enough 1GB pages are available for the dataset (~2.14GB needs 3 pages).
    #[must_use]
    pub fn has_enough_1g_for_dataset(&self) -> bool {
        self.free_1g >= 3
    }
}

/// Check if 1GB huge pages are available for dataset allocation.
#[allow(dead_code)]
#[must_use]
pub fn one_gb_pages_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        HugePageStatus::get().has_enough_1g_for_dataset()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(all(target_os = "linux", not(miri)))]
fn linux_read_sysfs_usize(path: &str) -> usize {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(all(target_os = "linux", not(miri)))]
fn linux_1g_kernel_configured() -> bool {
    // Check /proc/cmdline for hugepagesz=1G
    std::fs::read_to_string("/proc/cmdline")
        .map(|s| s.contains("hugepagesz=1G") || s.contains("hugepagesz=1g"))
        .unwrap_or(false)
}

/// Print huge page diagnostic information to stderr.
///
/// This is useful for troubleshooting 1GB huge page configuration.
pub fn print_huge_page_diagnostics() {
    eprintln!("=== Huge Page Diagnostics ===");

    #[cfg(target_os = "linux")]
    {
        let status = HugePageStatus::get();
        eprintln!("Platform: Linux");
        eprintln!();
        eprintln!("1GB Huge Pages:");
        eprintln!(
            "  Kernel configured (cmdline): {}",
            status.kernel_1g_configured
        );
        eprintln!("  Pages configured: {}", status.configured_1g);
        eprintln!("  Pages free: {}", status.free_1g);
        eprintln!();
        eprintln!("2MB Huge Pages:");
        eprintln!("  Pages configured: {}", status.configured_2m);
        eprintln!("  Pages free: {}", status.free_2m);
        eprintln!();

        if !status.kernel_1g_configured && status.configured_1g == 0 {
            eprintln!("To enable 1GB pages, add to kernel boot parameters:");
            eprintln!("  hugepagesz=1G hugepages=3 default_hugepagesz=1G");
            eprintln!();
            eprintln!("Or at runtime (requires root, may fail if memory is fragmented):");
            eprintln!("  echo 3 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages");
        } else if status.free_1g < 3 {
            eprintln!(
                "Need 3 x 1GB pages for dataset. Current free: {}",
                status.free_1g
            );
            eprintln!("Allocate more (requires root):");
            eprintln!("  echo 3 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages");
        } else {
            eprintln!("1GB huge pages are available for dataset allocation.");
        }
    }

    #[cfg(target_os = "windows")]
    {
        eprintln!("Platform: Windows");
        eprintln!();
        eprintln!("1GB huge pages are NOT supported on Windows.");
        eprintln!("Windows only supports 2MB large pages via VirtualAlloc.");
        eprintln!();
        eprintln!("To use 2MB large pages on Windows:");
        eprintln!("  1. Run as Administrator");
        eprintln!("  2. Enable 'Lock pages in memory' privilege in Local Security Policy");
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        eprintln!("Platform: Other");
        eprintln!();
        eprintln!("Huge pages are not implemented for this platform.");
    }

    eprintln!("=============================");
}

/// Huge page size options for Linux.
/// Windows only supports 2MB large pages via VirtualAlloc; 1GB pages are not available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HugePageSize {
    /// Use the system default (typically 2MB).
    Default,
    /// Request 1GB huge pages (Linux only, requires kernel configuration).
    /// Set `OXIDE_RANDOMX_HUGE_1G=1` to enable. Falls back to default if unavailable.
    OneGigabyte,
}

impl HugePageSize {
    /// Returns the page size in bytes, or None for system default.
    #[allow(dead_code)]
    pub fn size_bytes(self) -> Option<usize> {
        match self {
            HugePageSize::Default => None,
            HugePageSize::OneGigabyte => Some(1024 * 1024 * 1024),
        }
    }
}

/// Large-page request policy for scratchpad/dataset allocations.
#[derive(Clone, Copy, Debug)]
pub enum LargePageRequest {
    /// Disable large-page allocation.
    Disabled,
    /// Enable large pages using the system default size.
    Enabled { label: &'static str },
    /// Enabled with explicit huge page size preference (Linux only).
    EnabledWithSize {
        label: &'static str,
        size: HugePageSize,
    },
}

impl LargePageRequest {
    pub const fn disabled() -> Self {
        Self::Disabled
    }

    pub const fn enabled(label: &'static str) -> Self {
        Self::Enabled { label }
    }

    /// Create a large page request with an explicit size preference.
    pub const fn enabled_with_size(label: &'static str, size: HugePageSize) -> Self {
        Self::EnabledWithSize { label, size }
    }

    fn label(self) -> &'static str {
        match self {
            LargePageRequest::Disabled => "buffer",
            LargePageRequest::Enabled { label } => label,
            LargePageRequest::EnabledWithSize { label, .. } => label,
        }
    }

    fn is_enabled(self) -> bool {
        matches!(
            self,
            LargePageRequest::Enabled { .. } | LargePageRequest::EnabledWithSize { .. }
        )
    }

    fn requested_size(self) -> HugePageSize {
        match self {
            LargePageRequest::EnabledWithSize { size, .. } => size,
            _ => HugePageSize::Default,
        }
    }
}

/// Heap-allocated, aligned buffer with optional large-page backing.
pub struct AlignedBuf {
    ptr: NonNull<u8>,
    len: usize,
    kind: AllocKind,
    large_pages: bool,
    /// The huge page size actually used (if large_pages is true).
    huge_page_size: Option<usize>,
}

impl AlignedBuf {
    /// Allocate a zeroed buffer with the requested alignment and page policy.
    pub fn new_with_large_pages(
        len: usize,
        align: usize,
        request: LargePageRequest,
    ) -> Result<Self> {
        if request.is_enabled() {
            let requested_size = request.requested_size();
            match try_large_page_alloc(len, align, requested_size) {
                Ok((ptr, kind, page_size)) => {
                    return Ok(Self {
                        ptr,
                        len,
                        kind,
                        large_pages: true,
                        huge_page_size: Some(page_size),
                    });
                }
                Err(err) => warn_large_pages_once(request.label(), &err),
            }
        }

        let layout = Layout::from_size_align(len, align)
            .map_err(|_| RandomXError::InvalidArgument("invalid layout"))?;
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr =
            NonNull::new(ptr).ok_or(RandomXError::AllocationFailed("aligned allocation failed"))?;
        #[cfg(target_os = "linux")]
        if request.is_enabled() {
            try_madvise_hugepage(ptr.as_ptr(), len);
        }
        Ok(Self {
            ptr,
            len,
            kind: AllocKind::Standard { layout },
            large_pages: false,
            huge_page_size: None,
        })
    }

    /// View the buffer as an immutable byte slice.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// View the buffer as a mutable byte slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Returns true if the buffer is backed by large pages.
    pub fn uses_large_pages(&self) -> bool {
        self.large_pages
    }

    /// Returns the huge page size in bytes if large pages are being used.
    /// Returns None if using standard pages.
    /// Returns the huge page size in bytes, if any.
    pub fn huge_page_size(&self) -> Option<usize> {
        self.huge_page_size
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe {
            match self.kind {
                AllocKind::Standard { layout } => {
                    dealloc(self.ptr.as_ptr(), layout);
                }
                #[cfg(all(target_os = "linux", not(miri)))]
                AllocKind::Mmap { len } => {
                    let _ = munmap(self.ptr.as_ptr().cast(), len);
                }
                #[cfg(target_os = "windows")]
                AllocKind::VirtualAlloc => {
                    let _ = VirtualFree(self.ptr.as_ptr().cast(), 0, MEM_RELEASE);
                }
            }
        }
    }
}

enum AllocKind {
    Standard {
        layout: Layout,
    },
    #[cfg(all(target_os = "linux", not(miri)))]
    Mmap {
        len: usize,
    },
    #[cfg(target_os = "windows")]
    VirtualAlloc,
}

fn warn_large_pages_once(label: &'static str, err: &str) {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "warning: large pages requested for {label} but unavailable ({err}); \
falling back to normal pages"
        );
    });
}

#[cfg(any(all(target_os = "linux", not(miri)), target_os = "windows"))]
fn round_up(value: usize, align: usize) -> Option<usize> {
    if !align.is_power_of_two() {
        return None;
    }
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

#[cfg(target_os = "windows")]
fn try_large_page_alloc(
    len: usize,
    align: usize,
    _requested_size: HugePageSize,
) -> StdResult<(NonNull<u8>, AllocKind, usize)> {
    // Windows only supports 2MB large pages via VirtualAlloc.
    // 1GB pages are not available to user-mode applications.
    try_large_page_alloc_windows(len, align)
}

#[cfg(target_os = "linux")]
fn try_large_page_alloc(
    len: usize,
    align: usize,
    requested_size: HugePageSize,
) -> StdResult<(NonNull<u8>, AllocKind, usize)> {
    try_large_page_alloc_linux(len, align, requested_size)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn try_large_page_alloc(
    _len: usize,
    _align: usize,
    _requested_size: HugePageSize,
) -> StdResult<(NonNull<u8>, AllocKind, usize)> {
    Err("unsupported platform".to_string())
}

#[cfg(all(target_os = "linux", miri))]
fn try_large_page_alloc_linux(
    _len: usize,
    _align: usize,
    _requested_size: HugePageSize,
) -> StdResult<(NonNull<u8>, AllocKind, usize)> {
    Err("large pages not supported under miri".to_string())
}

#[cfg(all(target_os = "linux", not(miri)))]
fn try_large_page_alloc_linux(
    len: usize,
    align: usize,
    requested_size: HugePageSize,
) -> StdResult<(NonNull<u8>, AllocKind, usize)> {
    // Try 1GB pages first if requested and available
    if requested_size == HugePageSize::OneGigabyte {
        if let Some(result) = try_1g_pages_linux(len, align) {
            return result;
        }
        // Fall through to default huge pages if 1G pages unavailable
        warn_1g_pages_fallback();
    }

    // Default: use system default huge page size (typically 2MB)
    let huge_size = linux_hugepage_size().unwrap_or(2 * 1024 * 1024);
    if huge_size < align {
        return Err("hugepage size smaller than alignment".to_string());
    }
    let alloc_len = round_up(len, huge_size).ok_or_else(|| "invalid hugepage size".to_string())?;
    let ptr = unsafe {
        mmap(
            core::ptr::null_mut(),
            alloc_len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON | MAP_HUGETLB,
            -1,
            0,
        )
    };
    if ptr == MAP_FAILED {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let ptr = NonNull::new(ptr as *mut u8).ok_or_else(|| "mmap returned null".to_string())?;
    Ok((ptr, AllocKind::Mmap { len: alloc_len }, huge_size))
}

/// Attempt to allocate using 1GB huge pages on Linux.
/// Returns None if 1GB pages are not available or allocation fails.
#[cfg(all(target_os = "linux", not(miri)))]
fn try_1g_pages_linux(
    len: usize,
    align: usize,
) -> Option<StdResult<(NonNull<u8>, AllocKind, usize)>> {
    const ONE_GB: usize = 1024 * 1024 * 1024;

    // Check if 1GB pages are configured in the kernel
    if !linux_1g_pages_available() {
        return None;
    }

    if ONE_GB < align {
        return Some(Err("1GB page size smaller than alignment".to_string()));
    }

    let alloc_len = round_up(len, ONE_GB)?;

    // MAP_HUGE_1GB = (30 << MAP_HUGE_SHIFT) where MAP_HUGE_SHIFT = 26
    // This equals 0x78000000
    const MAP_HUGE_1GB: i32 = 30 << 26;

    let ptr = unsafe {
        mmap(
            core::ptr::null_mut(),
            alloc_len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON | MAP_HUGETLB | MAP_HUGE_1GB,
            -1,
            0,
        )
    };

    if ptr == MAP_FAILED {
        // 1GB allocation failed, let caller fall back to default
        return None;
    }

    let ptr = match NonNull::new(ptr as *mut u8) {
        Some(p) => p,
        None => return Some(Err("mmap returned null".to_string())),
    };

    Some(Ok((ptr, AllocKind::Mmap { len: alloc_len }, ONE_GB)))
}

/// Check if 1GB huge pages are available on this Linux system.
#[cfg(all(target_os = "linux", not(miri)))]
fn linux_1g_pages_available() -> bool {
    use std::sync::OnceLock;
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        // Check /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
        // If this file exists and contains a non-zero value, 1GB pages are available
        let path = "/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages";
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let count: usize = content.trim().parse().unwrap_or(0);
                count > 0
            }
            Err(_) => false,
        }
    })
}

#[cfg(all(target_os = "linux", not(miri)))]
fn warn_1g_pages_fallback() {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        let status = HugePageStatus::get();
        if status.configured_1g == 0 {
            eprintln!(
                "info: 1GB huge pages requested but not configured in kernel; \
                 using 2MB huge pages instead"
            );
            eprintln!(
                "      To enable: add 'hugepagesz=1G hugepages=3' to kernel boot parameters"
            );
        } else if status.free_1g < 3 {
            eprintln!(
                "info: 1GB huge pages requested but only {} free (need 3 for dataset); \
                 using 2MB huge pages instead",
                status.free_1g
            );
            eprintln!(
                "      To allocate more: echo 3 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages"
            );
        } else {
            eprintln!(
                "warning: 1GB huge pages requested but allocation failed; \
                 using 2MB huge pages instead"
            );
        }
    });
}

#[cfg(all(target_os = "linux", not(miri)))]
fn linux_hugepage_size() -> Option<usize> {
    use std::sync::OnceLock;
    static HUGE: OnceLock<Option<usize>> = OnceLock::new();
    *HUGE.get_or_init(|| {
        let data = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in data.lines() {
            if let Some(rest) = line.strip_prefix("Hugepagesize:") {
                let mut parts = rest.split_whitespace();
                let value = parts.next()?.parse::<usize>().ok()?;
                let unit = parts.next().unwrap_or("kB");
                if unit.eq_ignore_ascii_case("kb") {
                    return Some(value * 1024);
                }
            }
        }
        None
    })
}

#[cfg(all(target_os = "linux", not(miri)))]
fn try_madvise_hugepage(ptr: *mut u8, len: usize) {
    unsafe {
        let _ = madvise(ptr.cast(), len, MADV_HUGEPAGE);
    }
}

#[cfg(all(target_os = "linux", miri))]
fn try_madvise_hugepage(_ptr: *mut u8, _len: usize) {}

#[cfg(target_os = "windows")]
fn try_large_page_alloc_windows(
    len: usize,
    align: usize,
) -> StdResult<(NonNull<u8>, AllocKind, usize)> {
    let page_size = unsafe { GetLargePageMinimum() } as usize;
    if page_size == 0 {
        return Err("large pages not supported".to_string());
    }
    if page_size < align {
        return Err("large page size smaller than alignment".to_string());
    }
    let alloc_len =
        round_up(len, page_size).ok_or_else(|| "invalid large page size".to_string())?;
    let _ = enable_large_pages_privilege();
    let ptr = unsafe {
        VirtualAlloc(
            core::ptr::null_mut(),
            alloc_len,
            MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES,
            PAGE_READWRITE,
        )
    };
    if ptr.is_null() {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let ptr =
        NonNull::new(ptr as *mut u8).ok_or_else(|| "VirtualAlloc returned null".to_string())?;
    Ok((ptr, AllocKind::VirtualAlloc, page_size))
}

#[cfg(all(target_os = "linux", not(miri)))]
use core::ffi::c_void;
#[cfg(all(target_os = "linux", not(miri)))]
const PROT_READ: i32 = 0x1;
#[cfg(all(target_os = "linux", not(miri)))]
const PROT_WRITE: i32 = 0x2;
#[cfg(all(target_os = "linux", not(miri)))]
const MAP_PRIVATE: i32 = 0x02;
#[cfg(all(target_os = "linux", not(miri)))]
const MAP_ANON: i32 = 0x20;
#[cfg(all(target_os = "linux", not(miri)))]
const MAP_HUGETLB: i32 = 0x40000;
#[cfg(all(target_os = "linux", not(miri)))]
const MADV_HUGEPAGE: i32 = 14;
#[cfg(all(target_os = "linux", not(miri)))]
const MAP_FAILED: *mut c_void = !0 as *mut c_void;

#[cfg(all(target_os = "linux", not(miri)))]
extern "C" {
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: isize,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;
}

#[cfg(target_os = "windows")]
use core::ffi::c_void;
#[cfg(target_os = "windows")]
type Handle = *mut c_void;
#[cfg(target_os = "windows")]
type LpVoid = *mut c_void;
#[cfg(target_os = "windows")]
type Dword = u32;
#[cfg(target_os = "windows")]
const MEM_COMMIT: Dword = 0x1000;
#[cfg(target_os = "windows")]
const MEM_RESERVE: Dword = 0x2000;
#[cfg(target_os = "windows")]
const MEM_RELEASE: Dword = 0x8000;
#[cfg(target_os = "windows")]
const MEM_LARGE_PAGES: Dword = 0x20000000;
#[cfg(target_os = "windows")]
const PAGE_READWRITE: Dword = 0x04;

#[cfg(target_os = "windows")]
const TOKEN_ADJUST_PRIVILEGES: Dword = 0x20;
#[cfg(target_os = "windows")]
const TOKEN_QUERY: Dword = 0x8;
#[cfg(target_os = "windows")]
const SE_PRIVILEGE_ENABLED: Dword = 0x2;
#[cfg(target_os = "windows")]
const ERROR_NOT_ALL_ASSIGNED: Dword = 1300;

#[cfg(target_os = "windows")]
#[repr(C)]
struct Luid {
    low_part: Dword,
    high_part: i32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct LuidAndAttributes {
    luid: Luid,
    attributes: Dword,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct TokenPrivileges {
    count: Dword,
    privileges: LuidAndAttributes,
}

#[cfg(target_os = "windows")]
fn enable_large_pages_privilege() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| unsafe {
        let mut token: Handle = core::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }
        let mut luid = Luid {
            low_part: 0,
            high_part: 0,
        };
        if LookupPrivilegeValueW(core::ptr::null(), SE_LOCK_MEMORY_NAME.as_ptr(), &mut luid) == 0 {
            let _ = CloseHandle(token);
            return false;
        }
        let tp = TokenPrivileges {
            count: 1,
            privileges: LuidAndAttributes {
                luid,
                attributes: SE_PRIVILEGE_ENABLED,
            },
        };
        let ok = AdjustTokenPrivileges(
            token,
            0,
            &tp,
            core::mem::size_of::<TokenPrivileges>() as Dword,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        ) != 0;
        let err = GetLastError();
        let _ = CloseHandle(token);
        ok && err != ERROR_NOT_ALL_ASSIGNED
    })
}

#[cfg(target_os = "windows")]
const SE_LOCK_MEMORY_NAME: [u16; 22] = [
    'S' as u16, 'e' as u16, 'L' as u16, 'o' as u16, 'c' as u16, 'k' as u16, 'M' as u16, 'e' as u16,
    'm' as u16, 'o' as u16, 'r' as u16, 'y' as u16, 'P' as u16, 'r' as u16, 'i' as u16, 'v' as u16,
    'i' as u16, 'l' as u16, 'e' as u16, 'g' as u16, 'e' as u16, 0,
];

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(addr: LpVoid, size: usize, alloc_type: Dword, protect: Dword) -> LpVoid;
    fn VirtualFree(addr: LpVoid, size: usize, free_type: Dword) -> i32;
    fn GetLargePageMinimum() -> usize;
    fn GetCurrentProcess() -> Handle;
    fn GetLastError() -> Dword;
}

#[cfg(target_os = "windows")]
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, desired_access: Dword, token: *mut Handle) -> i32;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut Luid) -> i32;
    fn AdjustTokenPrivileges(
        token: Handle,
        disable_all_privileges: i32,
        new_state: *const TokenPrivileges,
        buffer_length: Dword,
        previous_state: *mut TokenPrivileges,
        return_length: *mut Dword,
    ) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huge_page_status_get_succeeds() {
        // Should not panic on any platform
        let status = HugePageStatus::get();
        println!("HugePageStatus: {:?}", status);

        // On non-Linux, all values should be 0
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(status.configured_1g, 0);
            assert_eq!(status.free_1g, 0);
            assert!(!status.kernel_1g_configured);
        }
    }

    #[test]
    fn huge_page_status_methods() {
        let status = HugePageStatus {
            configured_1g: 3,
            free_1g: 3,
            configured_2m: 100,
            free_2m: 50,
            kernel_1g_configured: true,
        };
        assert!(status.has_1g_pages());
        assert!(status.has_enough_1g_for_dataset());

        let status_low = HugePageStatus {
            configured_1g: 2,
            free_1g: 2,
            configured_2m: 100,
            free_2m: 50,
            kernel_1g_configured: true,
        };
        assert!(status_low.has_1g_pages());
        assert!(!status_low.has_enough_1g_for_dataset()); // Needs 3

        let status_none = HugePageStatus {
            configured_1g: 0,
            free_1g: 0,
            configured_2m: 100,
            free_2m: 50,
            kernel_1g_configured: false,
        };
        assert!(!status_none.has_1g_pages());
        assert!(!status_none.has_enough_1g_for_dataset());
    }

    #[test]
    fn aligned_buf_fallback_works() {
        // Even when 1GB pages are requested, should fall back gracefully
        let result = AlignedBuf::new_with_large_pages(
            64 * 1024, // 64KB - small allocation
            64,
            LargePageRequest::enabled_with_size("test", HugePageSize::OneGigabyte),
        );

        // Should succeed with some allocation (1GB, 2MB, or standard pages)
        assert!(result.is_ok(), "Allocation should succeed with fallback");
        let buf = result.unwrap();

        // Verify memory is accessible
        let slice = buf.as_slice();
        assert_eq!(slice.len(), 64 * 1024);
        assert_eq!(slice[0], 0); // Should be zeroed
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "requires 1GB huge pages configured"]
    fn test_1gb_huge_pages() {
        if !one_gb_pages_available() {
            eprintln!("Skipping: 1GB huge pages not available");
            return;
        }

        let buf = AlignedBuf::new_with_large_pages(
            64 * 1024,
            64,
            LargePageRequest::enabled_with_size("test-1g", HugePageSize::OneGigabyte),
        )
        .expect("1GB huge page allocation");

        assert!(buf.uses_large_pages());
        assert_eq!(buf.huge_page_size(), Some(1024 * 1024 * 1024));
    }

    #[test]
    fn huge_page_size_values() {
        assert_eq!(HugePageSize::Default.size_bytes(), None);
        assert_eq!(
            HugePageSize::OneGigabyte.size_bytes(),
            Some(1024 * 1024 * 1024)
        );
    }

    #[test]
    fn large_page_request_builder() {
        let disabled = LargePageRequest::disabled();
        assert!(!disabled.is_enabled());

        let enabled = LargePageRequest::enabled("test");
        assert!(enabled.is_enabled());
        assert_eq!(enabled.requested_size(), HugePageSize::Default);

        let enabled_1g = LargePageRequest::enabled_with_size("test-1g", HugePageSize::OneGigabyte);
        assert!(enabled_1g.is_enabled());
        assert_eq!(enabled_1g.requested_size(), HugePageSize::OneGigabyte);
    }
}
