#![cfg(feature = "jit")]

use oxide_randomx::jit::ExecutableBuffer;

#[cfg(target_arch = "x86_64")]
#[test]
fn execbuf_can_execute_code() {
    let mut buf = ExecutableBuffer::new(16).expect("buffer");
    assert!(!buf.is_rx());

    // mov eax, 0x2a; ret
    let code: [u8; 6] = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
    buf.write(&code).expect("write code");
    buf.finalize_rx().expect("finalize");
    assert!(buf.is_rx());

    type TestFn = unsafe extern "C" fn() -> u32;
    let func: TestFn = unsafe { buf.as_fn_ptr() };
    let out = unsafe { func() };
    assert_eq!(out, 0x2a);

    assert!(buf.write(&code).is_err());
    assert!(buf.finalize_rx().is_err());
}
