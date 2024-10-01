mod nizk;

use std::ffi::CString;
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn run_benchmark() -> *mut c_char {
    let result = nizk::run_benchmark();
    let c_str = CString::new(result).unwrap();
    c_str.into_raw()
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    unsafe {
        if s.is_null() { return }
        CString::from_raw(s)
    };
}