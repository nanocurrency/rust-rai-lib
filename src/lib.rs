#![cfg_attr(not(feature = "threading"), allow(unused_imports))]

extern crate blake2;
extern crate byteorder;
extern crate digest;
extern crate ed25519_dalek;
extern crate hex;
extern crate libc;
extern crate nanocurrency_types;
extern crate num_cpus;
extern crate rand;
extern crate serde;
extern crate serde_json;

#[cfg(test)]
mod tests;

use blake2::Blake2b;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use digest::{Digest, VariableOutput};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use nanocurrency_types::{Account, BlockInner, Network};
use rand::{OsRng, Rng};
use serde::Deserialize;
use std::cmp;
use std::ffi::CStr;
use std::ptr;
use std::slice;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool};
use std::sync::mpsc;
use std::thread;

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
pub unsafe extern "C" fn xrb_uint256_to_address(
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
    let mut blake2b = <Blake2b as VariableOutput>::new(32).expect("Invalid hash length");
    blake2b.input(slice::from_raw_parts(seed as *const u8, 32));
    let mut seed_bytes = [0u8; 4];
    LittleEndian::write_u32(&mut seed_bytes, index as u32);
    blake2b.input(&seed_bytes);
    blake2b
        .variable_result(slice::from_raw_parts_mut(destination as *mut u8, 32))
        .expect("Invalid hash result length");
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

#[cfg(feature = "threading")]
fn generate_work(root: [u8; 32]) -> u64 {
    let n_threads = cmp::max(num_cpus::get(), 1);
    let mut threads = Vec::with_capacity(n_threads);
    let finished = Arc::new(AtomicBool::new(false));
    let channel = mpsc::channel();
    for i in 0..n_threads {
        let root = root.clone();
        let send_result = channel.0.clone();
        let finished = finished.clone();
        threads.push(thread::spawn(move || {
            let mut work = (u64::max_value() / (n_threads as u64)) * (i as u64);
            let threshold = nanocurrency_types::work_threshold(Network::Live);
            while !finished.load(atomic::Ordering::Relaxed) {
                if nanocurrency_types::work_value(&root, work) >= threshold {
                    finished.store(true, atomic::Ordering::Relaxed);
                    let _ = send_result.send(work);
                }
                work += 1;
            }
        }));
    }
    channel.1.recv().expect("Failed to generate work")
}

#[cfg(not(feature = "threading"))]
fn generate_work(root: [u8; 32]) -> u64 {
    let mut work = 0;
    let threshold = nanocurrency_types::work_threshold(Network::Live);
    while nanocurrency_types::work_value(&root, work) < threshold {
        work += 1;
    }
    work
}

#[no_mangle]
pub unsafe extern "C" fn xrb_work_transaction(
    transaction: *const libc::c_char,
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
    let root = block_inner.root_bytes().clone();
    let work = generate_work(root);
    {
        let json_map = match json.as_object_mut() {
            Some(x) => x,
            None => return ptr::null(), // shouldn't be possible
        };
        let mut work_bytes = [0u8; 8];
        BigEndian::write_u64(&mut work_bytes, work);
        json_map.insert(
            "work".to_string(),
            serde_json::Value::String(hex::encode(work_bytes)),
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

#[no_mangle]
pub unsafe extern "C" fn xrb_work(root_ptr: *const libc::c_char) -> u64 {
    let mut root = [0u8; 32];
    root.clone_from_slice(slice::from_raw_parts(root_ptr as *const u8, 32));
    generate_work(root)
}
