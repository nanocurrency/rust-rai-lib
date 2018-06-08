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
    assert!(xrb_hash_transaction(b"\xc3\x28".as_ptr() as _).is_null());
}
