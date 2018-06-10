use std::ffi::{CStr, CString};
use *;

const HASH_TESTS: &[(&str, Option<&str>)] = &[
    ("", None),
    ("{}", None),
    ("abc", None),
    (
        r#"{
            "type":"state",
            "previous":"0000000000000000000000000000000000000000000000000000000000000000",
            "account":"xrb_3igf8hd4sjshoibbbkeitmgkp1o6ug4xads43j6e4gqkj5xk5o83j8ja9php",
            "representative":"xrb_3p1asma84n8k84joneka776q4egm5wwru3suho9wjsfyuem8j95b3c78nw8j",
            "balance":"1",
            "link":"1EF0AD02257987B48030CC8D38511D3B2511672F33AF115AD09E18A86A8355A8"
        }"#,
        Some("FC5A7FB777110A858052468D448B2DF22B648943C097C0608D1E2341007438B0"),
    ),
    (
        r#"{
            "type":"state",
            "previous":"0000000000000000000000000000000000000000000000000000000000000000",
            "account":"xrb_3igf8hd4sjshoibbbkeitmgkp1o6ug4xads43j6e4gqkj5xk5o83j8ja9php",
            "representative":"xrb_3p1asma84n8k84joneka776q4egm5wwru3suho9wjsfyuem8j95b3c78nw8j",
            "balance":"1",
            "link":"1EF0AD02257987B48030CC8D38511D3B2511672F33AF115AD09E18A86A8355A8",
            "signature":"593D865DDCC6018F197C0EACD15E5CED3DAF134EDFAF6553DB9C1D0E11DBDCBBE1B01E1A4C6D4378289567E59BA122DA5BFD49729AA6C2B0FC9E592A546B4F09",
            "work":"0000000000001234"
        }"#,
        Some("FC5A7FB777110A858052468D448B2DF22B648943C097C0608D1E2341007438B0"),
    ),
    (
        r#"{
            "link":"00",
            "previous":"0",
            "balance":"100000000000000000000000000",
            "representative":"nano_1w77aapnijnm5mo16r3xtpqu7n459r61fqpcdt3kxfmz8gtqgzbozswxmduy",
            "account":"xrb_34xpajsxasoqksskk9fqkps8jtb1a1fbxgp5usheernizw6w6wajksbgfak8",
            "type":"state"
        }"#,
        Some("22A27E8D0BB947D465D50BFB3D0B6FA420B8B802A69D3388937D8A4F1CD59740"),
    ),
    (r#"{"type":"invalid"}"#, None),
];

#[test]
fn hash() {
    for (input, expected_output) in HASH_TESTS {
        let out = unsafe {
            let input = CString::new(*input).expect("Null byte in input");
            let out = xrb_hash_transaction(input.as_ptr() as _);
            if out.is_null() {
                None
            } else {
                Some(
                    CStr::from_ptr(out)
                        .to_str()
                        .expect("Invalid UTF-8 in result"),
                )
            }
        };
        assert_eq!(&out, expected_output);
    }
}

#[test]
fn hash_invalid_utf8() {
    unsafe {
        assert!(xrb_hash_transaction(b"\xc3\x28".as_ptr() as _).is_null());
    }
}

#[test]
fn deterministic_key() {
    unsafe {
        let seed = [0u8; 32];
        let mut out = [0u8; 32];
        xrb_seed_key(seed.as_ptr() as _, 0, out.as_mut_ptr() as _);
        assert_eq!(
            hex::encode_upper(out),
            "9F0E444C69F77A49BD0BE89DB92C38FE713E0963165CCA12FAF5712D7657120F"
        );
    }
}
