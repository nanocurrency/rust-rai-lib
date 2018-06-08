extern crate blake2;
extern crate byteorder;
extern crate digest;
extern crate ed25519_dalek;
extern crate hex;
extern crate libc;
extern crate nanocurrency_types;
extern crate rand;
extern crate serde;
extern crate serde_json;

#[cfg(test)]
mod tests;

use blake2::Blake2b;
use byteorder::{ByteOrder, LittleEndian};
use digest::{Digest, FixedOutput};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use nanocurrency_types::{Account, BlockInner};
use rand::{OsRng, Rng};
use serde::Deserialize;
use std::ffi::CStr;
use std::mem;
use std::ptr;
use std::slice;

#[no_mangle]
pub unsafe extern "C" fn xrb_uint128_to_dec(
    source: *const libc::c_char,
    destination: *mut libc::c_char,
) {
    let source = slice::from_raw_parts(source as *const u8, 16);
    let number = LittleEndian::read_u128(source);
    let decimal = number.to_string();
    assert!(decimal.len() <= 32);
    ptr::copy_nonoverlapping(decimal.as_ptr(), destination as *mut u8, decimal.len());
    for i in decimal.len()..32 {
        *destination.offset(i as isize) = 0;
    }
}

#[no_mangle]
pub unsafe extern "C" fn xrb_uint256_to_string(
    source: *const libc::c_char,
    destination: *mut libc::c_char,
) {
    let source = slice::from_raw_parts(source as *const u8, 32);
    let hex_string = hex::encode_upper(source);
    assert_eq!(hex_string.len(), 64);
    ptr::copy_nonoverlapping(hex_string.as_ptr(), destination as *mut u8, 64);
}

#[no_mangle]
pub unsafe extern "C" fn xrb_uint256_to_account(
    source: *const libc::c_char,
    destination: *mut libc::c_char,
) {
    let mut account = Account([0u8; 32]);
    account
        .0
        .copy_from_slice(slice::from_raw_parts(source as *const u8, 32));
    let account_string = account.to_string();
    assert!(account_string.len() <= 65);
    ptr::copy_nonoverlapping(
        account_string.as_ptr(),
        destination as *mut u8,
        account_string.len(),
    );
    for i in account_string.len()..65 {
        *destination.offset(i as isize) = 0;
    }
}

#[no_mangle]
pub unsafe extern "C" fn xrb_uint512_to_string(
    source: *const libc::c_char,
    destination: *mut libc::c_char,
) {
    let source = slice::from_raw_parts(source as *const u8, 64);
    let hex_string = hex::encode_upper(source);
    assert_eq!(hex_string.len(), 128);
    ptr::copy_nonoverlapping(
        hex_string.as_ptr(),
        destination as *mut u8,
        hex_string.len(),
    );
}

#[no_mangle]
pub unsafe extern "C" fn xrb_uint128_from_dec(
    source: *const libc::c_char,
    destination: *mut libc::c_char,
) -> libc::c_int {
    let source = CStr::from_ptr(source);
    let source = match source.to_str() {
        Ok(x) => x,
        Err(_) => return 1,
    };
    let number: u128 = match source.parse() {
        Ok(x) => x,
        Err(_) => return 1,
    };
    let destination = slice::from_raw_parts_mut(destination as *mut u8, 16);
    LittleEndian::write_u128(destination, number);
    0
}

#[no_mangle]
pub unsafe extern "C" fn xrb_uint256_from_string(
    source: *const libc::c_char,
    destination: *mut libc::c_char,
) -> libc::c_int {
    let bytes = match hex::decode(CStr::from_ptr(source).to_bytes()) {
        Ok(x) => x,
        Err(_) => return 1,
    };
    if bytes.len() != 32 {
        return 1;
    }
    ptr::copy_nonoverlapping(bytes.as_ptr(), destination as *mut u8, bytes.len());
    0
}

#[no_mangle]
pub unsafe extern "C" fn xrb_uint512_from_string(
    source: *const libc::c_char,
    destination: *mut libc::c_char,
) -> libc::c_int {
    let bytes = match hex::decode(CStr::from_ptr(source).to_bytes()) {
        Ok(x) => x,
        Err(_) => return 1,
    };
    if bytes.len() != 64 {
        return 1;
    }
    ptr::copy_nonoverlapping(bytes.as_ptr(), destination as *mut u8, bytes.len());
    0
}

#[no_mangle]
pub unsafe extern "C" fn xrb_valid_address(account: *const libc::c_char) -> libc::c_int {
    let account = CStr::from_ptr(account);
    let account = match account.to_str() {
        Ok(x) => x,
        Err(_) => return 1,
    };
    match account.parse::<Account>() {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn xrb_generate_random(destination: *mut libc::c_char) {
    let mut rng = OsRng::new().expect("Failed to create OsRng");
    rng.fill(slice::from_raw_parts_mut(destination, 32));
}

#[no_mangle]
pub unsafe extern "C" fn xrb_seed_key(
    seed: *const libc::c_char,
    index: libc::c_int,
    destination: *mut libc::c_char,
) {
    let mut blake2b = Blake2b::default();
    blake2b.input(slice::from_raw_parts(seed as *const u8, 32));
    let seed_bytes: [u8; mem::size_of::<libc::c_int>()] = mem::transmute(index.to_le());
    blake2b.input(&seed_bytes);
    let result = blake2b.fixed_result();
    assert_eq!(result.len(), 32);
    ptr::copy_nonoverlapping(
        result.as_slice().as_ptr(),
        destination as *mut u8,
        result.len(),
    );
}

#[no_mangle]
pub unsafe extern "C" fn xrb_key_account(key: *const libc::c_char, destination: *mut libc::c_char) {
    let secret_key = SecretKey::from_bytes(slice::from_raw_parts(key as *const u8, 32))
        .expect("Invalid key length");
    let public_key = PublicKey::from_secret::<Blake2b>(&secret_key);
    let bytes = public_key.to_bytes();
    assert_eq!(bytes.len(), 32);
    ptr::copy_nonoverlapping(bytes.as_ptr(), destination as *mut u8, bytes.len())
}

#[no_mangle]
pub unsafe extern "C" fn xrb_hash_transaction(
    transaction: *const libc::c_char,
) -> *const libc::c_char {
    let transaction = CStr::from_ptr(transaction);
    let transaction = match transaction.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null(),
    };
    let block_inner: BlockInner = match serde_json::from_str(transaction) {
        Ok(x) => x,
        Err(_) => return ptr::null(),
    };
    let hash = block_inner.get_hash();
    let string = hex::encode_upper(hash.0);
    let ret = libc::malloc(string.len() + 1) as *mut libc::c_char;
    if ret.is_null() {
        return ptr::null();
    }
    ptr::copy_nonoverlapping(string.as_ptr() as *const libc::c_char, ret, string.len());
    *ret.offset(string.len() as isize) = 0; // null terminator
    ret
}

#[no_mangle]
pub unsafe extern "C" fn xrb_sign_transaction(
    transaction: *const libc::c_char,
    private_key: *const libc::c_char,
) -> *const libc::c_char {
    let transaction = CStr::from_ptr(transaction);
    let transaction = match transaction.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null(),
    };
    let mut json = match serde_json::from_str::<serde_json::Value>(transaction) {
        Ok(x) => x,
        Err(_) => return ptr::null(),
    };
    let block_inner: BlockInner = match BlockInner::deserialize(&json) {
        Ok(x) => x,
        Err(_) => return ptr::null(),
    };
    let hash = block_inner.get_hash();
    let secret_key = SecretKey::from_bytes(slice::from_raw_parts(private_key as *const u8, 32))
        .expect("Invalid key length");
    let public_key = PublicKey::from_secret::<Blake2b>(&secret_key);
    let keypair = Keypair {
        secret: secret_key,
        public: public_key,
    };
    let signature = keypair.sign::<Blake2b>(&hash.0);
    {
        let json_map = match json.as_object_mut() {
            Some(x) => x,
            None => return ptr::null(), // shouldn't be possible
        };
        json_map.insert(
            "signature".to_string(),
            serde_json::Value::String(hex::encode_upper(&signature.to_bytes() as &[u8])),
        );
    }
    let string = serde_json::to_string(&json).expect("Failed to serialize json");
    let ret = libc::malloc(string.len() + 1) as *mut libc::c_char;
    if ret.is_null() {
        return ptr::null();
    }
    ptr::copy_nonoverlapping(string.as_ptr() as *const libc::c_char, ret, string.len());
    *ret.offset(string.len() as isize) = 0; // null terminator
    ret
}
