#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub type randomx_flags = u32;

#[repr(C)]
pub struct randomx_dataset {
    _unused: [u8; 0],
}

#[repr(C)]
pub struct randomx_cache {
    _unused: [u8; 0],
}

#[repr(C)]
pub struct randomx_vm {
    _unused: [u8; 0],
}

extern "C" {
    pub fn randomx_alloc_cache(flags: randomx_flags) -> *mut randomx_cache;
    pub fn randomx_init_cache(cache: *mut randomx_cache, key: *const ::std::os::raw::c_void, keySize: usize);
    pub fn randomx_release_cache(cache: *mut randomx_cache);
    pub fn randomx_alloc_dataset(flags: randomx_flags) -> *mut randomx_dataset;
    pub fn randomx_dataset_item_count() -> ::std::os::raw::c_ulong;
    pub fn randomx_init_dataset(
        dataset: *mut randomx_dataset,
        cache: *mut randomx_cache,
        startItem: ::std::os::raw::c_ulong,
        itemCount: ::std::os::raw::c_ulong,
    );
    pub fn randomx_release_dataset(dataset: *mut randomx_dataset);
    pub fn randomx_create_vm(
        flags: randomx_flags,
        cache: *mut randomx_cache,
        dataset: *mut randomx_dataset,
    ) -> *mut randomx_vm;
    pub fn randomx_vm_set_cache(machine: *mut randomx_vm, cache: *mut randomx_cache);
    pub fn randomx_vm_set_dataset(machine: *mut randomx_vm, dataset: *mut randomx_dataset);
    pub fn randomx_destroy_vm(machine: *mut randomx_vm);
    pub fn randomx_calculate_hash(
        machine: *mut randomx_vm,
        input: *const ::std::os::raw::c_void,
        input_size: usize,
        output: *mut ::std::os::raw::c_void,
    );
}
