use std::ffi::CStr;
use std::ptr;

extern crate libc;

extern crate nanocurrency_types;
use nanocurrency_types::BlockInner;

extern crate serde_json;

extern crate hex;

#[cfg(test)]
mod tests;

#[no_mangle]
pub extern fn xrb_hash_transaction(transaction: *const libc::c_char) -> *const libc::c_char {
    let transaction = unsafe { CStr::from_ptr(transaction) };
    let transaction = match transaction.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null(),
    };
    let block_inner: BlockInner = match serde_json::from_str(transaction) {
        Ok(x) => x,
        Err(_) => return ptr::null(),
    };
    let hash = block_inner.get_hash();
    let hash_s = hex::encode_upper(&hash.0);
    unsafe {
        let ret = libc::malloc(hash_s.len() + 1) as *mut libc::c_char;
        if ret.is_null() {
            return ptr::null();
        }
        ptr::copy_nonoverlapping(hash_s.as_ptr() as *const libc::c_char, ret, hash_s.len());
        *ret.offset(hash_s.len() as isize) = 0; // null terminator
        ret
    }
}
