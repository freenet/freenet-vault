//! Operation requests and results (protocol 12.5), and SubmitRecord (12.4),
//! which shares the request header.
//!
//! Batch differs from protocol revision 6: it carries `expected_public_key`
//! after the slot, and the vault refuses the Batch when the slot holds a
//! different key (approved 2026-11-23, not yet in the documents; see
//! DESIGN-NOTES.md).

use crate::bounds::*;
use crate::codec::{Malformed, Reader, Result, Writer};
use crate::frame::{self, types};

/// `proof_kind 1`: a delegate caller's pointer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerProof {
    pub author_vk: [u8; 32],
    pub app_id: Vec<u8>,
    pub record: [u8; 100],
}

/// `request_id 8 ; proof_kind 1 ; [author_vk 32 ; app_id_len 1 ; app_id ; record 100]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub request_id: u64,
    /// `None` is proof_kind 0 (pages and native apps).
    pub proof: Option<CallerProof>,
}

impl RequestHeader {
    fn read(r: &mut Reader) -> Result<Self> {
        let request_id = r.u64("request_id")?;
        let proof = match r.u8("proof_kind")? {
            0 => None,
            1 => {
                let author_vk = r.array("author_vk")?;
                let app_id = read_app_id(r)?;
                let record = r.array("record")?;
                Some(CallerProof {
                    author_vk,
                    app_id,
                    record,
                })
            }
            _ => return Err(Malformed("proof_kind")),
        };
        Ok(Self { request_id, proof })
    }

    fn write(&self, w: &mut Writer) {
        w.u64(self.request_id);
        match &self.proof {
            None => {
                w.u8(0);
            }
            Some(p) => {
                w.u8(1)
                    .bytes(&p.author_vk)
                    .u8(p.app_id.len() as u8)
                    .bytes(&p.app_id)
                    .bytes(&p.record);
            }
        }
    }
}

fn read_app_id(r: &mut Reader) -> Result<Vec<u8>> {
    let len = r.u8("app_id_len")? as usize;
    if len == 0 || len > MAX_APP_ID {
        return Err(Malformed("app_id_len"));
    }
    Ok(r.take(len, "app_id")?.to_vec())
}

fn read_slot(r: &mut Reader) -> Result<Vec<u8>> {
    let len = r.u8("slot_len")? as usize;
    if len == 0 || len > MAX_SLOT {
        return Err(Malformed("slot_len"));
    }
    Ok(r.take(len, "slot")?.to_vec())
}

fn write_slot(w: &mut Writer, slot: &[u8]) {
    w.u8(slot.len() as u8).bytes(slot);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchItem {
    /// `op 0x01 ; data_len 4 (0..=65536) ; data`
    Sign(Vec<u8>),
    /// `op 0x02 ; peer 32`
    KeyAgreement([u8; 32]),
    /// `op 0x03 ; context_len 2 (1..=256, UTF-8) ; context ; data_len 4 (0..=65536) ; data`
    Derive { context: String, data: Vec<u8> },
}

pub const ITEM_SIGN: u8 = 0x01;
pub const ITEM_KEY_AGREEMENT: u8 = 0x02;
pub const ITEM_DERIVE: u8 = 0x03;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// `mode 1 ; slot_len 1 ; slot`. `slot: None` is self-named (mode 1,
    /// slot_len 0): the slot becomes the new public key.
    Generate {
        slot: Option<Vec<u8>>,
    },
    Import {
        slot: Vec<u8>,
        seed: [u8; 32],
        replace: bool,
    },
    Delete {
        slot: Vec<u8>,
    },
    PublicKey {
        slot: Vec<u8>,
    },
    List {
        after: Vec<u8>,
        max: u16,
    },
    Batch {
        slot: Vec<u8>,
        expected_public_key: [u8; 32],
        items: Vec<BatchItem>,
    },
    Export {
        slot: Vec<u8>,
    },
}

impl Operation {
    pub fn frame_type(&self) -> u8 {
        match self {
            Self::Generate { .. } => types::GENERATE,
            Self::Import { .. } => types::IMPORT,
            Self::Delete { .. } => types::DELETE,
            Self::PublicKey { .. } => types::PUBLIC_KEY,
            Self::List { .. } => types::LIST,
            Self::Batch { .. } => types::BATCH,
            Self::Export { .. } => types::EXPORT,
        }
    }

    /// The slot the operation names, if any.
    pub fn slot(&self) -> Option<&[u8]> {
        match self {
            Self::Generate { slot } => slot.as_deref(),
            Self::Import { slot, .. }
            | Self::Delete { slot }
            | Self::PublicKey { slot }
            | Self::Batch { slot, .. }
            | Self::Export { slot } => Some(slot),
            Self::List { .. } => None,
        }
    }
}

/// An operation request: `RequestHeader ; body ; ext_len 2 ; ext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub header: RequestHeader,
    pub op: Operation,
    pub ext: Vec<u8>,
}

/// Is this frame type an operation request this crate decodes?
pub fn is_operation(frame_type: u8) -> bool {
    (types::GENERATE..=types::EXPORT).contains(&frame_type)
}

impl Request {
    /// Reads only the request id, for answering a request that fails to
    /// decode. Zero when even that is unreadable.
    pub fn peek_request_id(body: &[u8]) -> u64 {
        Reader::new(body).u64("request_id").unwrap_or(0)
    }

    pub fn decode(frame_type: u8, body: &[u8]) -> Result<Self> {
        if body.len() > MAX_REQUEST_BODY {
            return Err(Malformed("request over 1 MiB"));
        }
        let mut r = Reader::new(body);
        let header = RequestHeader::read(&mut r)?;
        let op = match frame_type {
            types::GENERATE => {
                let mode = r.u8("mode")?;
                let slot_len = r.u8("slot_len")? as usize;
                match (mode, slot_len) {
                    (1, 0) => Operation::Generate { slot: None },
                    (0, n) if (1..=MAX_SLOT).contains(&n) => Operation::Generate {
                        slot: Some(r.take(n, "slot")?.to_vec()),
                    },
                    _ => return Err(Malformed("generate mode/slot_len")),
                }
            }
            types::IMPORT => {
                let slot = read_slot(&mut r)?;
                let seed = r.array("seed")?;
                let replace = r.bool("replace")?;
                Operation::Import {
                    slot,
                    seed,
                    replace,
                }
            }
            types::DELETE => Operation::Delete {
                slot: read_slot(&mut r)?,
            },
            types::PUBLIC_KEY => Operation::PublicKey {
                slot: read_slot(&mut r)?,
            },
            types::LIST => {
                let after_len = r.u8("after_len")? as usize;
                if after_len > MAX_LIST_AFTER {
                    return Err(Malformed("after_len"));
                }
                let after = r.take(after_len, "after")?.to_vec();
                let max = r.u16("max")?;
                if max == 0 || max as usize > MAX_LIST {
                    return Err(Malformed("list max"));
                }
                Operation::List { after, max }
            }
            types::BATCH => {
                let slot = read_slot(&mut r)?;
                let expected_public_key = r.array("expected_public_key")?;
                let count = r.u16("count")? as usize;
                if count == 0 || count > MAX_BATCH_ITEMS {
                    return Err(Malformed("batch count"));
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(read_item(&mut r)?);
                }
                Operation::Batch {
                    slot,
                    expected_public_key,
                    items,
                }
            }
            types::EXPORT => Operation::Export {
                slot: read_slot(&mut r)?,
            },
            _ => return Err(Malformed("not an operation")),
        };
        let ext = r.ext()?;
        r.finish()?;
        Ok(Self { header, op, ext })
    }

    pub fn encode_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.header.write(&mut w);
        match &self.op {
            Operation::Generate { slot: None } => {
                w.u8(1).u8(0);
            }
            Operation::Generate { slot: Some(s) } => {
                w.u8(0);
                write_slot(&mut w, s);
            }
            Operation::Import {
                slot,
                seed,
                replace,
            } => {
                write_slot(&mut w, slot);
                w.bytes(seed).u8(*replace as u8);
            }
            Operation::Delete { slot }
            | Operation::PublicKey { slot }
            | Operation::Export { slot } => {
                write_slot(&mut w, slot);
            }
            Operation::List { after, max } => {
                w.u8(after.len() as u8).bytes(after).u16(*max);
            }
            Operation::Batch {
                slot,
                expected_public_key,
                items,
            } => {
                write_slot(&mut w, slot);
                w.bytes(expected_public_key).u16(items.len() as u16);
                for it in items {
                    match it {
                        BatchItem::Sign(d) => {
                            w.u8(ITEM_SIGN).u32(d.len() as u32).bytes(d);
                        }
                        BatchItem::KeyAgreement(p) => {
                            w.u8(ITEM_KEY_AGREEMENT).bytes(p);
                        }
                        BatchItem::Derive { context, data } => {
                            w.u8(ITEM_DERIVE)
                                .u16(context.len() as u16)
                                .bytes(context.as_bytes())
                                .u32(data.len() as u32)
                                .bytes(data);
                        }
                    }
                }
            }
        }
        w.ext(&self.ext);
        w.into_vec()
    }

    pub fn encode(&self) -> Vec<u8> {
        frame::encode(self.op.frame_type(), &self.encode_body())
    }
}

fn read_item(r: &mut Reader) -> Result<BatchItem> {
    match r.u8("item op")? {
        ITEM_SIGN => {
            let len = r.u32("data_len")? as usize;
            if len > MAX_ITEM_DATA {
                return Err(Malformed("sign data_len"));
            }
            Ok(BatchItem::Sign(r.take(len, "data")?.to_vec()))
        }
        ITEM_KEY_AGREEMENT => Ok(BatchItem::KeyAgreement(r.array("peer")?)),
        ITEM_DERIVE => {
            let clen = r.u16("context_len")? as usize;
            if clen == 0 || clen > MAX_DERIVE_CONTEXT {
                return Err(Malformed("context_len"));
            }
            let context = core::str::from_utf8(r.take(clen, "context")?)
                .map_err(|_| Malformed("context utf-8"))?
                .to_owned();
            let len = r.u32("data_len")? as usize;
            if len > MAX_ITEM_DATA {
                return Err(Malformed("derive data_len"));
            }
            Ok(BatchItem::Derive {
                context,
                data: r.take(len, "data")?.to_vec(),
            })
        }
        _ => Err(Malformed("item op")),
    }
}

/// SubmitRecord (0x21): `RequestHeader ; author_vk 32 ; app_id_len 1 (1..=64) ; app_id ; record 100 ; ext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitRecord {
    pub header: RequestHeader,
    pub author_vk: [u8; 32],
    pub app_id: Vec<u8>,
    pub record: [u8; 100],
    pub ext: Vec<u8>,
}

impl SubmitRecord {
    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.len() > MAX_REQUEST_BODY {
            return Err(Malformed("request over 1 MiB"));
        }
        let mut r = Reader::new(body);
        let header = RequestHeader::read(&mut r)?;
        let author_vk = r.array("author_vk")?;
        let app_id = read_app_id(&mut r)?;
        let record = r.array("record")?;
        let ext = r.ext()?;
        r.finish()?;
        Ok(Self {
            header,
            author_vk,
            app_id,
            record,
            ext,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.header.write(&mut w);
        w.bytes(&self.author_vk)
            .u8(self.app_id.len() as u8)
            .bytes(&self.app_id)
            .bytes(&self.record)
            .ext(&self.ext);
        frame::encode(types::SUBMIT_RECORD, &w.into_vec())
    }
}

/// One Batch item's result: `status 1 ; len 2 ; bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemResult {
    /// 0 ok; 11 forbidden signing domain.
    pub status: u8,
    pub bytes: Vec<u8>,
}

pub const ITEM_OK: u8 = 0;
pub const ITEM_FORBIDDEN_SIGNING_DOMAIN: u8 = 11;

/// One List row: `slot_len 1 ; slot ; public_key 32 ; status 1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListItem {
    pub slot: Vec<u8>,
    pub public_key: [u8; 32],
    /// 0 ok; 1 corrupt (public key informational only); 2 unusable.
    pub status: u8,
}

pub const LIST_OK: u8 = 0;
pub const LIST_CORRUPT: u8 = 1;
pub const LIST_UNUSABLE: u8 = 2;

/// Operation results (0xA0..=0xA4): `request_id 8 ; body ; ext_len 2 ; ext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpResult {
    Key { slot: Vec<u8>, public_key: [u8; 32] },
    Ok,
    List { items: Vec<ListItem>, more: bool },
    Batch(Vec<ItemResult>),
    Export { seed: [u8; 32] },
}

impl OpResult {
    pub fn frame_type(&self) -> u8 {
        match self {
            Self::Key { .. } => types::KEY_RESULT,
            Self::Ok => types::OK,
            Self::List { .. } => types::LIST_RESULT,
            Self::Batch(_) => types::BATCH_RESULT,
            Self::Export { .. } => types::EXPORT_RESULT,
        }
    }

    pub fn encode(&self, request_id: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(request_id);
        match self {
            Self::Key { slot, public_key } => {
                write_slot(&mut w, slot);
                w.bytes(public_key);
            }
            Self::Ok => {}
            Self::List { items, more } => {
                w.u16(items.len() as u16);
                for it in items {
                    write_slot(&mut w, &it.slot);
                    w.bytes(&it.public_key).u8(it.status);
                }
                w.u8(*more as u8);
            }
            Self::Batch(results) => {
                w.u16(results.len() as u16);
                for r in results {
                    w.u8(r.status).u16(r.bytes.len() as u16).bytes(&r.bytes);
                }
            }
            Self::Export { seed } => {
                w.bytes(seed);
            }
        }
        w.ext(&[]);
        frame::encode(self.frame_type(), &w.into_vec())
    }

    /// Decodes a result body; returns `(request_id, result)`.
    pub fn decode(frame_type: u8, body: &[u8]) -> Result<(u64, Self)> {
        let mut r = Reader::new(body);
        let request_id = r.u64("request_id")?;
        let out = match frame_type {
            types::KEY_RESULT => Self::Key {
                slot: read_slot(&mut r)?,
                public_key: r.array("public_key")?,
            },
            types::OK => Self::Ok,
            types::LIST_RESULT => {
                let count = r.u16("count")? as usize;
                if count > MAX_LIST {
                    return Err(Malformed("list count"));
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(ListItem {
                        slot: read_slot(&mut r)?,
                        public_key: r.array("public_key")?,
                        status: r.u8("status")?,
                    });
                }
                Self::List {
                    items,
                    more: r.bool("more")?,
                }
            }
            types::BATCH_RESULT => {
                let count = r.u16("count")? as usize;
                if count == 0 || count > MAX_BATCH_ITEMS {
                    return Err(Malformed("batch count"));
                }
                let mut results = Vec::with_capacity(count);
                for _ in 0..count {
                    let status = r.u8("status")?;
                    let len = r.u16("len")? as usize;
                    results.push(ItemResult {
                        status,
                        bytes: r.take(len, "bytes")?.to_vec(),
                    });
                }
                Self::Batch(results)
            }
            types::EXPORT_RESULT => Self::Export {
                seed: r.array("seed")?,
            },
            _ => return Err(Malformed("not a result")),
        };
        r.ext()?;
        r.finish()?;
        Ok((request_id, out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Frame;

    fn page(request_id: u64) -> RequestHeader {
        RequestHeader {
            request_id,
            proof: None,
        }
    }

    fn round_trip(req: Request) {
        let bytes = req.encode();
        let f = Frame::decode(&bytes).unwrap();
        assert_eq!(f.frame_type, req.op.frame_type());
        assert_eq!(Request::decode(f.frame_type, f.body).unwrap(), req);
    }

    #[test]
    fn every_operation_round_trips() {
        let slot = vec![0xAB; 32];
        let proof = RequestHeader {
            request_id: u64::MAX,
            proof: Some(CallerProof {
                author_vk: [3; 32],
                app_id: b"river.chat-delegate".to_vec(),
                record: [4; 100],
            }),
        };
        for op in [
            Operation::Generate { slot: None },
            Operation::Generate {
                slot: Some(slot.clone()),
            },
            Operation::Import {
                slot: slot.clone(),
                seed: [5; 32],
                replace: true,
            },
            Operation::Delete { slot: slot.clone() },
            Operation::PublicKey { slot: slot.clone() },
            Operation::List {
                after: vec![],
                max: 256,
            },
            Operation::Batch {
                slot: slot.clone(),
                expected_public_key: [6; 32],
                items: vec![
                    BatchItem::Sign(vec![]),
                    BatchItem::KeyAgreement([7; 32]),
                    BatchItem::Derive {
                        context: "ctx é".into(),
                        data: vec![1; 36],
                    },
                ],
            },
            Operation::Export { slot: slot.clone() },
        ] {
            round_trip(Request {
                header: page(1),
                op: op.clone(),
                ext: vec![],
            });
            round_trip(Request {
                header: proof.clone(),
                op,
                ext: vec![9; 3],
            });
        }
    }

    /// Positive vector for the PublicKey request from a page, with the
    /// Batch layout's `expected_public_key` placement pinned too.
    #[test]
    fn request_vectors() {
        let req = Request {
            header: page(0x0102030405060708),
            op: Operation::PublicKey {
                slot: vec![0xEE; 2],
            },
            ext: vec![],
        };
        assert_eq!(
            req.encode(),
            [
                b'F', b'V', b'L', b'T', 1, 0x83, 0, 0, 0, 14, // envelope
                1, 2, 3, 4, 5, 6, 7, 8, 0, // request_id, proof_kind 0
                2, 0xEE, 0xEE, // slot
                0, 0, // ext
            ]
        );
        let batch = Request {
            header: page(0),
            op: Operation::Batch {
                slot: vec![0xEE],
                expected_public_key: [0x11; 32],
                items: vec![BatchItem::KeyAgreement([0x22; 32])],
            },
            ext: vec![],
        };
        let mut body = vec![0; 8];
        body.push(0);
        body.extend_from_slice(&[1, 0xEE]);
        body.extend_from_slice(&[0x11; 32]);
        body.extend_from_slice(&[0, 1, 0x02]);
        body.extend_from_slice(&[0x22; 32]);
        body.extend_from_slice(&[0, 0]);
        assert_eq!(batch.encode_body(), body);
    }

    fn decode_body(ft: u8, body: &[u8]) -> Result<Request> {
        Request::decode(ft, body)
    }

    #[test]
    fn malformed_requests() {
        let h = [0u8; 9]; // request_id + proof_kind 0
        let with = |rest: &[u8]| {
            let mut b = h.to_vec();
            b.extend_from_slice(rest);
            b
        };
        // proof_kind 2.
        let mut bad_proof = h.to_vec();
        bad_proof[8] = 2;
        bad_proof.extend_from_slice(&[1, 1, 0, 0]);
        assert!(decode_body(types::DELETE, &bad_proof).is_err());
        // slot_len 0 and 65.
        assert!(decode_body(types::DELETE, &with(&[0, 0, 0])).is_err());
        let mut s65 = vec![65];
        s65.extend_from_slice(&[0; 65]);
        s65.extend_from_slice(&[0, 0]);
        assert!(decode_body(types::DELETE, &with(&s65)).is_err());
        // Generate: self-named with a slot, named with none, unknown mode.
        assert!(decode_body(types::GENERATE, &with(&[1, 1, 9, 0, 0])).is_err());
        assert!(decode_body(types::GENERATE, &with(&[0, 0, 0, 0])).is_err());
        assert!(decode_body(types::GENERATE, &with(&[2, 0, 0, 0])).is_err());
        assert!(decode_body(types::GENERATE, &with(&[1, 0, 0, 0])).is_ok());
        // Import replace 2.
        let mut imp = vec![1, 9];
        imp.extend_from_slice(&[0; 32]);
        imp.push(2);
        imp.extend_from_slice(&[0, 0]);
        assert!(decode_body(types::IMPORT, &with(&imp)).is_err());
        // List max 0 and 257, after_len 65.
        assert!(decode_body(types::LIST, &with(&[0, 0, 0, 0, 0])).is_err());
        assert!(decode_body(types::LIST, &with(&[0, 1, 1, 0, 0])).is_err());
        assert!(decode_body(types::LIST, &with(&[0, 1, 0, 0, 0])).is_ok());
        // Batch count 0 and an unknown item op.
        let batch = |count: u16, items: &[u8]| {
            let mut b = vec![1, 9];
            b.extend_from_slice(&[0; 32]);
            b.extend_from_slice(&count.to_be_bytes());
            b.extend_from_slice(items);
            b.extend_from_slice(&[0, 0]);
            with(&b)
        };
        assert!(decode_body(types::BATCH, &batch(0, &[])).is_err());
        assert!(decode_body(types::BATCH, &batch(1, &[0x04])).is_err());
        // Sign over 65,536 bytes.
        let mut big = vec![ITEM_SIGN];
        big.extend_from_slice(&65_537u32.to_be_bytes());
        big.extend_from_slice(&vec![0; 65_537]);
        assert!(decode_body(types::BATCH, &batch(1, &big)).is_err());
        let mut at = vec![ITEM_SIGN];
        at.extend_from_slice(&65_536u32.to_be_bytes());
        at.extend_from_slice(&vec![0; 65_536]);
        assert!(decode_body(types::BATCH, &batch(1, &at)).is_ok());
        // Derive: empty context, non-UTF-8 context.
        let mut d0 = vec![ITEM_DERIVE, 0, 0];
        d0.extend_from_slice(&[0, 0, 0, 0]);
        assert!(decode_body(types::BATCH, &batch(1, &d0)).is_err());
        let mut dbad = vec![ITEM_DERIVE, 0, 1, 0xFF];
        dbad.extend_from_slice(&[0, 0, 0, 0]);
        assert!(decode_body(types::BATCH, &batch(1, &dbad)).is_err());
        // Trailing byte after ext.
        let mut trailing = with(&[1, 9, 0, 0]);
        trailing.push(0);
        assert!(decode_body(types::DELETE, &trailing).is_err());
        // Over 1 MiB.
        assert!(decode_body(types::DELETE, &vec![0; 1024 * 1024 + 1]).is_err());
        // app_id_len 0 in a proof.
        let mut p = vec![0; 8];
        p.push(1);
        p.extend_from_slice(&[0; 32]);
        p.push(0);
        p.extend_from_slice(&[0; 100]);
        p.extend_from_slice(&[1, 9, 0, 0]);
        assert!(decode_body(types::DELETE, &p).is_err());
    }

    #[test]
    fn results_round_trip() {
        let cases = vec![
            OpResult::Key {
                slot: vec![1; 32],
                public_key: [2; 32],
            },
            OpResult::Ok,
            OpResult::List {
                items: vec![
                    ListItem {
                        slot: vec![1; 32],
                        public_key: [2; 32],
                        status: LIST_OK,
                    },
                    ListItem {
                        slot: vec![3; 32],
                        public_key: [4; 32],
                        status: LIST_CORRUPT,
                    },
                ],
                more: true,
            },
            OpResult::List {
                items: vec![],
                more: false,
            },
            OpResult::Batch(vec![
                ItemResult {
                    status: ITEM_OK,
                    bytes: vec![5; 64],
                },
                ItemResult {
                    status: ITEM_FORBIDDEN_SIGNING_DOMAIN,
                    bytes: vec![],
                },
            ]),
            OpResult::Export { seed: [6; 32] },
        ];
        for c in cases {
            let bytes = c.encode(42);
            let f = Frame::decode(&bytes).unwrap();
            assert_eq!(OpResult::decode(f.frame_type, f.body).unwrap(), (42, c));
        }
    }

    #[test]
    fn submit_record_round_trips() {
        let s = SubmitRecord {
            header: page(3),
            author_vk: [1; 32],
            app_id: b"river.chat-delegate".to_vec(),
            record: [2; 100],
            ext: vec![],
        };
        let bytes = s.encode();
        let f = Frame::decode(&bytes).unwrap();
        assert_eq!(f.frame_type, types::SUBMIT_RECORD);
        assert_eq!(SubmitRecord::decode(f.body).unwrap(), s);
    }
}
