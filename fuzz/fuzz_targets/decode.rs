//! Every v1 decoder, and the build-private ones, on arbitrary bytes: none may
//! panic, and what a decoder accepts is canonical. Envelope, requests,
//! SubmitRecord, Poke and entries re-encode to the same bytes. Result and
//! status frames accept an extension of any length and do not keep it, so for
//! those the decoded value must survive an encode and a decode.
#![no_main]

use freenet_vault::consent::Pending;
use freenet_vault::storage::index::Index;
use freenet_vault::succ::Succ;
use freenet_vault_common::entry::Entry;
use freenet_vault_common::frame::{self, types, Frame};
use freenet_vault_common::ops::{is_operation, OpResult, Request, SubmitRecord};
use freenet_vault_common::status::{Poke, Status};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = Frame::decode(data) {
        assert_eq!(frame::encode(f.frame_type, f.body).unwrap(), data);
        // Each body decoder only for the frame type that carries it.
        if is_operation(f.frame_type) {
            if let Ok(r) = Request::decode(f.frame_type, f.body) {
                assert_eq!(r.encode().unwrap(), data);
            }
        }
        if f.frame_type == types::SUBMIT_RECORD {
            if let Ok(s) = SubmitRecord::decode(f.body) {
                assert_eq!(s.encode().unwrap(), data);
            }
        }
        if f.frame_type == types::POKE {
            if let Ok(p) = Poke::decode(f.body) {
                assert_eq!(p.encode().unwrap(), data);
            }
        }
        if f.frame_type >= types::KEY_RESULT {
            if let Ok((rid, r)) = OpResult::decode(f.frame_type, f.body) {
                let again = r.encode(rid).unwrap();
                let g = Frame::decode(&again).unwrap();
                assert_eq!(OpResult::decode(g.frame_type, g.body).unwrap(), (rid, r));
            }
        }
        if let Ok(s) = Status::decode(f.frame_type, f.body) {
            let again = s.encode().unwrap();
            let g = Frame::decode(&again).unwrap();
            assert_eq!(Status::decode(g.frame_type, g.body).unwrap(), s);
        }
    }
    if let Ok(e) = Entry::decode(data) {
        assert_eq!(e.encode().unwrap(), data);
    }
    // Persisted state is parsed on every call: a panic here is a trap that
    // bricks the vault.
    if let Ok(i) = Index::decode(data) {
        assert_eq!(Index::decode(&i.encode()).unwrap(), i);
    }
    // Arbitrary bytes almost never carry a valid checksum, so also seal them:
    // that reaches the body parser.
    if let Ok(i) = Index::decode(&Index::seal(data)) {
        assert_eq!(Index::decode(&i.encode()).unwrap(), i);
    }
    let _ = Succ::decode(data);
    if let Some(p) = Pending::decode(data) {
        assert_eq!(Pending::decode(&p.encode()), Some(p));
    }
});
