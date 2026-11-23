//! Every v1 decoder on arbitrary bytes: none may panic, and what a decoder
//! accepts must re-encode to the same bytes.
#![no_main]

use freenet_vault_common::entry::Entry;
use freenet_vault_common::frame::{self, Frame};
use freenet_vault_common::ops::{OpResult, Request, SubmitRecord};
use freenet_vault_common::status::{Poke, Status};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = Frame::decode(data) {
        assert_eq!(frame::encode(f.frame_type, f.body).unwrap(), data);
        if let Ok(r) = Request::decode(f.frame_type, f.body) {
            assert_eq!(r.encode().unwrap(), data);
        }
        if let Ok(s) = SubmitRecord::decode(f.body) {
            assert_eq!(s.encode().unwrap(), data);
        }
        if let Ok((rid, r)) = OpResult::decode(f.frame_type, f.body) {
            assert_eq!(r.encode(rid).unwrap(), data);
        }
        let _ = Status::decode(f.frame_type, f.body);
        let _ = Poke::decode(f.body);
    }
    if let Ok(e) = Entry::decode(data) {
        assert_eq!(e.encode().unwrap(), data);
    }
});
