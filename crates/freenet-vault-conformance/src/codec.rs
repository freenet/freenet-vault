//! The abstraction between the model's values and the library's bytes.
//!
//! Identities: build version `v` has code hash [`code`]`(v)` and delegate key
//! [`dkey`]`(v)`; its records are signed by one domain author key. A model
//! key slot `s` is the 32-byte slot [`slot32`]`(s)`; a seed `n` is
//! [`Tables::seed32`]`(n)`; a caller mark of caller `c` at record version
//! `r` is the entry `(0x02, author_vk(c) || app_id(c))` holding `c`'s record
//! at version `r`. Digests: the model's 64-bit digest of an entry and the
//! library's BLAKE3 digest of its bytes are paired when either is computed;
//! likewise manifest digests.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use ed25519_dalek::{Signer, SigningKey};
use freenet_vault::storage::index::{self as lix, Handover, IndexEntry, State};
use freenet_vault::storage::names;
use freenet_vault::trace::Note as LNote;
use freenet_vault::{CallerDelegate, Domain, PageContainer};
use freenet_vault_common::entry::Entry as LEntry;
use freenet_vault_common::frame::{self, types, Frame as WFrame};
use freenet_vault_common::handover::{self as wh, chunk_status as cs, cstatus, outcome};
use freenet_vault_common::hash;
use freenet_vault_common::record::{signing_message, PointerRecord};
use freenet_vault_model::build::{BuildDef, Note, Params};
use freenet_vault_model::types::*;

pub const NCALLERS: u16 = 4;
const AUTHOR_SEED: [u8; 32] = [0xD0; 32];
const APP_ID: &[u8] = b"conf.vault";
const CONTAINER: [u8; 32] = [0xC0; 32];
const PUBLISHER_SEED: [u8; 32] = [0xB0; 32];
const GARBLED: &[u8] = b"\xFFgarbled";

pub fn vk(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn sign_record(seed: &[u8; 32], app_id: &[u8], version: u32, code_hash: [u8; 32]) -> [u8; 100] {
    let sk = SigningKey::from_bytes(seed);
    let msg = signing_message(&sk.verifying_key().to_bytes(), app_id, version, &code_hash);
    let mut out = [0u8; 100];
    out[..4].copy_from_slice(&version.to_be_bytes());
    out[4..36].copy_from_slice(&code_hash);
    out[36..].copy_from_slice(&sk.sign(&msg).to_bytes());
    out
}

pub fn code(v: Ver) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"conformance code");
    h.update(&v.to_be_bytes());
    *h.finalize().as_bytes()
}

pub fn dkey(v: Ver) -> [u8; 32] {
    hash::delegate_key_empty_params(&code(v))
}

pub fn author_vk() -> [u8; 32] {
    thread_local!(static A: [u8; 32] = vk(&AUTHOR_SEED));
    A.with(|a| *a)
}

#[allow(non_snake_case)]
pub fn P() -> [u8; 32] {
    thread_local!(static PART: [u8; 32] = hash::partition_id(&author_vk(), APP_ID));
    PART.with(|p| *p)
}

pub fn page_id() -> [u8; 32] {
    hash::contract_instance_id(&CONTAINER, &vk(&PUBLISHER_SEED))
}

pub fn caller_vk(c: u16) -> [u8; 32] {
    vk(&[0xE0u8.wrapping_add(c as u8); 32])
}

/// Caller `c`'s app id, `conf.caller<c>` (any `c`: the world's damage may
/// flip a key bit, 0x100).
pub fn caller_app(c: u16) -> &'static [u8] {
    thread_local!(static A: RefCell<HashMap<u16, &'static [u8]>> = RefCell::new(HashMap::new()));
    A.with(|m| {
        *m.borrow_mut()
            .entry(c)
            .or_insert_with(|| Box::leak(format!("conf.caller{c}").into_bytes().into_boxed_slice()))
    })
}

/// The model keys the bridge names: those the generator uses and the same
/// with bit 0x100 flipped (the world's "changed key field" damage, 15.3).
fn model_keys() -> impl Iterator<Item = u16> {
    (0..64u16).chain(0x100..0x140)
}

pub fn caller_record(c: u16, version: u32) -> [u8; 100] {
    thread_local!(static C: RefCell<HashMap<(u16, u32), [u8; 100]>> = RefCell::new(HashMap::new()));
    C.with(|m| {
        *m.borrow_mut().entry((c, version)).or_insert_with(|| {
            let mut h = blake3::Hasher::new();
            h.update(b"conformance caller code");
            h.update(&c.to_be_bytes());
            h.update(&version.to_be_bytes());
            sign_record(
                &[0xE0u8.wrapping_add(c as u8); 32],
                caller_app(c),
                version,
                *h.finalize().as_bytes(),
            )
        })
    })
}

/// The caller record version a mark entry holds.
pub fn mark_version(e: &LEntry) -> Option<u32> {
    let r: [u8; 100] = e.content.as_slice().try_into().ok()?;
    Some(PointerRecord::decode(&r).version)
}

pub fn rec_bytes(r: Rec) -> [u8; 100] {
    thread_local!(static C: RefCell<HashMap<Rec, [u8; 100]>> = RefCell::new(HashMap::new()));
    C.with(|m| {
        *m.borrow_mut().entry(r).or_insert_with(|| {
            let ch = if r.withdrawal { [0; 32] } else { code(r.v) };
            sign_record(&AUTHOR_SEED, APP_ID, r.v, ch)
        })
    })
}

pub fn rec_of(b: &[u8; 100]) -> Rec {
    let p = PointerRecord::decode(b);
    Rec {
        v: p.version,
        withdrawal: p.is_withdrawal(),
    }
}

/// The domain of build `def` (cached: `Domain` holds static slices).
pub fn domain(def: &BuildDef, p: &Params) -> Domain {
    thread_local!(static D: RefCell<HashMap<(Ver, usize), Domain>> = RefCell::new(HashMap::new()));
    D.with(|m| {
        *m.borrow_mut()
            .entry((def.v, p.max_entries))
            .or_insert_with(|| {
                let preds: Vec<(u32, [u8; 32])> =
                    def.preds.iter().map(|v| (*v, code(*v))).collect();
                let callers: Vec<CallerDelegate> = (0..NCALLERS)
                    .map(|c| CallerDelegate {
                        author_vk: caller_vk(c),
                        app_id: caller_app(c),
                        min_version: 0,
                    })
                    .collect();
                Domain {
                    author_vk: author_vk(),
                    app_id: APP_ID,
                    own_version: def.v,
                    predecessors: Box::leak(preds.into_boxed_slice()),
                    page_containers: Box::leak(Box::new([PageContainer {
                        code_hash: CONTAINER,
                        publisher_vk: vk(&PUBLISHER_SEED),
                    }])),
                    extra_page_ids: &[],
                    caller_delegates: Box::leak(callers.into_boxed_slice()),
                    delegate_frames: &[types::BATCH, types::PUBLIC_KEY, types::SUBMIT_RECORD],
                    publisher_keys: &[],
                    slot_len: Some(32),
                    max_key_slots: p.max_entries,
                    max_caller_marks: p.max_entries,
                    export_prompt: |_| "export?".into(),
                }
            })
    })
}

pub fn slot32(s: u16) -> [u8; 32] {
    let mut o = [0x5A; 32];
    o[30..].copy_from_slice(&s.to_be_bytes());
    o
}

pub fn seed_u32(s: &[u8; 32]) -> Option<u32> {
    if s[..28].iter().all(|b| *b == 0x77) {
        Some(u32::from_be_bytes(s[28..].try_into().unwrap()))
    } else {
        None
    }
}

fn key_bytes(kind: u8, key: u16) -> Vec<u8> {
    match kind {
        KIND_KEY => slot32(key).to_vec(),
        KIND_MARK => {
            let mut v = caller_vk(key).to_vec();
            v.extend_from_slice(caller_app(key));
            v
        }
        _ => {
            let mut o = vec![0x33; 32];
            o[30..].copy_from_slice(&key.to_be_bytes());
            o
        }
    }
}

/// The model key of a library entry key.
pub fn key_of(kind: u8, key: &[u8]) -> Option<u16> {
    match kind {
        KIND_KEY => {
            let s: [u8; 32] = key.try_into().ok()?;
            let k = u16::from_be_bytes([s[30], s[31]]);
            (slot32(k) == s).then_some(k)
        }
        KIND_MARK => {
            let app = key.get(32..)?;
            let c: u16 = std::str::from_utf8(app.strip_prefix(b"conf.caller")?)
                .ok()?
                .parse()
                .ok()?;
            (key_bytes(KIND_MARK, c) == key).then_some(c)
        }
        _ => {
            if key.len() != 32 {
                return None;
            }
            let k = u16::from_be_bytes([key[30], key[31]]);
            (key_bytes(kind, k) == key).then_some(k)
        }
    }
}

#[derive(Default)]
pub struct Tables {
    names: HashMap<Vec<u8>, SName>,
    d32: HashMap<[u8; 32], u64>,
    d64: HashMap<u64, ([u8; 32], u16)>,
    m32: HashMap<[u8; 32], u64>,
    m64: HashMap<u64, [u8; 32]>,
    pk: HashMap<[u8; 32], u32>,
    keys: HashMap<[u8; 32], Ver>,
    tids: HashMap<[u8; 32], (Ver, Rec)>,
    /// The exact bytes last written by a build for (name, value): the library reads
    /// back what it wrote even where the model's value is coarser. Keyed by the build: a record the index holds (`own_record`) names it.
    exact: HashMap<(Ver, SName, String), Vec<u8>>,
    pub lossy: BTreeMap<String, u64>,
    pub findings: Vec<String>,
}

impl Tables {
    pub fn finding(&mut self, f: String) {
        if self.findings.len() < 100_000 {
            self.findings.push(f);
        }
    }

    fn init_names(&mut self) {
        if !self.names.is_empty() {
            return;
        }
        let p = P();
        let mut put = |n: Vec<u8>, s: SName| {
            self.names.insert(n, s);
        };
        put(names::SUCC.to_vec(), SName::Succ);
        put(names::PARTS.to_vec(), SName::Parts);
        put(names::index(&p), SName::Idx);
        put(names::gc(&p), SName::Gc);
        put(names::gc2(&p), SName::Gc2);
        put(names::received_dropped(&p), SName::Rx);
        for v in 0..=200u32 {
            put(names::progress(v, &p), SName::X(v));
        }
        for kind in [KIND_KEY, KIND_MARK, KIND_UNKNOWN] {
            for key in model_keys() {
                for par in [false, true] {
                    put(
                        names::entry(&p, kind, &key_bytes(kind, key), par as u8),
                        SName::E((kind, key), par),
                    );
                }
            }
        }
        for v in 0..=200u32 {
            self.keys.insert(dkey(v), v);
            for pv in (10..=60).step_by(10) {
                for w in [false, true] {
                    let r = Rec { v, withdrawal: w };
                    self.tids
                        .insert(hash::transfer_id(&author_vk(), pv, &rec_bytes(r)), (pv, r));
                }
            }
        }
    }

    pub fn name_of(&mut self, key: &[u8]) -> Option<SName> {
        self.init_names();
        self.names.get(key).copied()
    }

    pub fn name_bytes(&self, n: SName) -> Vec<u8> {
        let p = P();
        match n {
            SName::Succ => names::SUCC.to_vec(),
            SName::Parts => names::PARTS.to_vec(),
            SName::Idx => names::index(&p),
            SName::Gc => names::gc(&p),
            SName::Gc2 => names::gc2(&p),
            SName::Rx => names::received_dropped(&p),
            SName::X(v) => names::progress(v, &p),
            SName::E((kind, key), par) => names::entry(&p, kind, &key_bytes(kind, key), par as u8),
        }
    }

    pub fn ver_of_key(&mut self, key: &[u8]) -> Option<Ver> {
        self.init_names();
        let k: [u8; 32] = key.try_into().ok()?;
        self.keys.get(&k).copied()
    }

    pub fn seed32(&mut self, n: u32) -> [u8; 32] {
        let mut s = [0x77; 32];
        s[28..].copy_from_slice(&n.to_be_bytes());
        self.pk
            .entry(freenet_vault::crypto::public_key(&s))
            .or_insert(n);
        s
    }

    pub fn seed_of_pk(&self, pk: &[u8; 32]) -> Option<u32> {
        self.pk.get(pk).copied()
    }

    // ---------------------------------------------------------------- entries

    fn content_bytes(&mut self, kind: u8, key: u16, content: u32) -> Vec<u8> {
        match kind {
            KIND_KEY => self.seed32(content).to_vec(),
            KIND_MARK => caller_record(key, content).to_vec(),
            _ => content.to_be_bytes().to_vec(),
        }
    }

    pub fn entry_bytes(&mut self, e: &Entry) -> Vec<u8> {
        let le = LEntry {
            kind: e.kind,
            eflags: e.flagged as u8,
            key: key_bytes(e.kind, e.key),
            content: self.content_bytes(e.kind, e.key, e.content),
            ext: e.ext.clone(),
        };
        let b = le.encode().expect("a model entry encodes");
        self.pair_digest(e.digest(), hash::entry_digest(&b), b.len());
        b
    }

    fn pair_digest(&mut self, d64: u64, d32: [u8; 32], len: usize) {
        self.d32.insert(d32, d64);
        self.d64.insert(d64, (d32, len as u16));
    }

    /// The model entry of library entry bytes, or None when they do not
    /// parse as one the model can name.
    pub fn entry_of(&mut self, b: &[u8]) -> Option<Entry> {
        let le = LEntry::decode(b).ok()?;
        if le.eflags & !1 != 0 {
            return None;
        }
        let key = key_of(le.kind, &le.key)?;
        let content = match le.kind {
            KIND_KEY => seed_u32(&le.content.as_slice().try_into().ok()?)?,
            KIND_MARK => {
                let r: [u8; 100] = le.content.as_slice().try_into().ok()?;
                (caller_record(key, PointerRecord::decode(&r).version) == r)
                    .then_some(PointerRecord::decode(&r).version)?
            }
            _ => u32::from_be_bytes(le.content.as_slice().try_into().ok()?),
        };
        let e = Entry {
            kind: le.kind,
            key,
            flagged: le.eflags & 1 != 0,
            content,
            ext: le.ext,
        };
        self.pair_digest(e.digest(), hash::entry_digest(b), b.len());
        Some(e)
    }

    pub fn d64_of(&mut self, d32: &[u8; 32]) -> u64 {
        if let Some(d) = self.d32.get(d32) {
            return *d;
        }
        // a digest of bytes the model cannot name: a stable stand-in
        let d = u64::from_be_bytes(d32[..8].try_into().unwrap()) | 1 << 63;
        self.d32.insert(*d32, d);
        self.d64.insert(d, (*d32, 0));
        d
    }

    pub fn d32_of(&mut self, d64: u64) -> [u8; 32] {
        if let Some((d, _)) = self.d64.get(&d64) {
            return *d;
        }
        let mut h = blake3::Hasher::new();
        h.update(b"conformance unknown digest");
        h.update(&d64.to_be_bytes());
        let d = *h.finalize().as_bytes();
        self.d32.insert(d, d64);
        self.d64.insert(d64, (d, 0));
        d
    }

    pub fn m64_of(&mut self, m32: &[u8; 32]) -> u64 {
        if m32 == &[0; 32] {
            return 0;
        }
        if let Some(m) = self.m32.get(m32) {
            return *m;
        }
        let m = u64::from_be_bytes(m32[..8].try_into().unwrap()) | 1 << 62;
        self.m32.insert(*m32, m);
        self.m64.insert(m, *m32);
        m
    }

    pub fn m32_of(&mut self, m64: u64) -> [u8; 32] {
        if m64 == 0 {
            return [0; 32];
        }
        if let Some(m) = self.m64.get(&m64) {
            return *m;
        }
        let mut h = blake3::Hasher::new();
        h.update(b"conformance unknown manifest");
        h.update(&m64.to_be_bytes());
        let m = *h.finalize().as_bytes();
        self.m32.insert(m, m64);
        self.m64.insert(m64, m);
        m
    }

    /// Pairs the manifest digests of a set of entry digests.
    fn pair_manifest(&mut self, d32s: &[[u8; 32]]) {
        let mut s32 = d32s.to_vec();
        s32.sort_unstable();
        let mut s64: Vec<u64> = d32s.iter().map(|d| self.d64_of(d)).collect();
        s64.sort_unstable();
        let m32 = hash::manifest_digest(&s32);
        let m64 = manifest_digest(&s64);
        self.m32.insert(m32, m64);
        self.m64.insert(m64, m32);
    }

    // ---------------------------------------------------------------- values

    pub fn decode(&mut self, own: Ver, n: SName, b: &[u8]) -> SVal {
        let v = self.decode_raw(own, n, b);
        let back = self.encode_raw(own, n, &v);
        let same =
            back == b || matches!(n, SName::Gc | SName::Gc2) && self.decode_raw(own, n, &back) == v;
        if !same {
            let k = match &v {
                SVal::Garbled => "garbled".to_string(),
                _ => build_kind(n).to_string(),
            };
            if k != "garbled" {
                *self.lossy.entry(k).or_insert(0) += 1;
            }
        }
        self.exact.insert((own, n, format!("{v:?}")), b.to_vec());
        v
    }

    pub fn encode(&mut self, own: Ver, n: SName, v: &SVal) -> Vec<u8> {
        if let Some(b) = self.exact.get(&(own, n, format!("{v:?}"))) {
            return b.clone();
        }
        self.encode_raw(own, n, v)
    }

    fn decode_raw(&mut self, own: Ver, n: SName, b: &[u8]) -> SVal {
        let v = match n {
            SName::Succ => freenet_vault::succ::Succ::decode(b).ok().map(|s| {
                SVal::Succ(Succ {
                    current: s.current.map(|r| rec_of(&r)),
                    withdrawal: s.withdrawal.map(|r| rec_of(&r)),
                })
            }),
            SName::Parts => {
                if !b.len().is_multiple_of(32) {
                    None
                } else if b.chunks(32).any(|c| c == P()) {
                    Some(SVal::Parts)
                } else {
                    Some(SVal::PartsEmpty)
                }
            }
            SName::Idx => lix::Index::decode(b)
                .ok()
                .and_then(|ix| self.index_of(own, &ix))
                .map(SVal::Idx),
            SName::E(..) => self.entry_of(b).map(SVal::E),
            SName::X(_) => freenet_vault::handover::decode_prog(b).and_then(|p| {
                let mut out = BTreeMap::new();
                for ((k, key), d) in p {
                    out.insert((k, key_of(k, &key)?), self.d64_of(&d));
                }
                Some(SVal::X(out))
            }),
            SName::Rx => freenet_vault::handover::decode_rx(b)
                .map(|s| SVal::Rx(s.iter().map(|d| self.d64_of(d)).collect())),
            SName::Gc | SName::Gc2 => freenet_vault::storage::decode_names(b).and_then(|l| {
                let mut out = BTreeSet::new();
                for x in l {
                    out.insert(self.name_of(&x)?);
                }
                Some(SVal::Gc(out))
            }),
        };
        v.unwrap_or(SVal::Garbled)
    }

    fn encode_raw(&mut self, own: Ver, n: SName, v: &SVal) -> Vec<u8> {
        match (n, v) {
            (_, SVal::Garbled) | (_, SVal::Undecryptable) => GARBLED.to_vec(),
            (_, SVal::Parts) => P().to_vec(),
            (_, SVal::PartsEmpty) => vec![],
            (_, SVal::Succ(s)) => freenet_vault::succ::Succ {
                current: s.current.map(rec_bytes),
                withdrawal: s.withdrawal.map(rec_bytes),
            }
            .encode(),
            (_, SVal::Idx(i)) => self.index_bytes(own, i).encode(),
            (_, SVal::E(e)) => self.entry_bytes(e),
            (_, SVal::X(m)) => {
                let mut p = BTreeMap::new();
                for ((k, key), d) in m {
                    p.insert((*k, key_bytes(*k, *key)), self.d32_of(*d));
                }
                freenet_vault::handover::encode_prog(&p)
            }
            (_, SVal::Rx(s)) => {
                let s: BTreeSet<[u8; 32]> = s.iter().map(|d| self.d32_of(*d)).collect();
                freenet_vault::handover::encode_rx(&s)
            }
            (_, SVal::Gc(g)) => {
                let l: Vec<Vec<u8>> = g.iter().map(|x| self.name_bytes(*x)).collect();
                freenet_vault::storage::encode_names(&l).unwrap_or_else(|_| GARBLED.to_vec())
            }
        }
    }

    fn index_of(&mut self, _own: Ver, ix: &lix::Index) -> Option<Index> {
        let mut entries = BTreeMap::new();
        let mut d32s = vec![];
        for ie in &ix.entries {
            let key = key_of(ie.kind, &ie.key)?;
            if ie.len > 0 {
                let d = self.d64_of(&ie.digest);
                self.d64.entry(d).and_modify(|x| x.1 = ie.len);
            }
            entries.insert(
                (ie.kind, key),
                IdxEnt {
                    parity: ie.parity == 1,
                    digest: self.d64_of(&ie.digest),
                },
            );
            d32s.push(ie.digest);
        }
        self.pair_manifest(&d32s);
        let tk = |t: &mut Self, x: Option<(u32, [u8; 32])>| x.map(|(v, m)| (v, t.m64_of(&m)));
        let w = WFields {
            taken_over: tk(self, ix.ho.taken_over),
            awaiting: ix.awaiting_retirement,
            paused: ix.ho.paused,
        };
        let state = match ix.state {
            State::None => PState::None {
                armed: ix.armed.map(|r| rec_of(&r)),
                confirmed: ix.ho.confirmed.iter().copied().collect(),
            },
            State::Writer => PState::Writer(w),
            State::Sealed => PState::Sealed {
                w,
                target: rec_of(&ix.peer_record?),
                m: self.m64_of(&ix.ho.m?),
            },
            State::Receiving => PState::Receiving {
                from: ix.ho.receiving_from,
                store_failed: ix.ho.store_failed,
            },
            State::Retired => PState::Retired {
                to: rec_of(&ix.peer_record?),
                m: self.m64_of(&ix.ho.m?),
                taken_over: w.taken_over,
            },
        };
        Some(Index {
            state,
            entries,
            problems: ix.problems,
            lost: ix.lost_entries,
        })
    }

    fn index_bytes(&mut self, own: Ver, i: &Index) -> lix::Index {
        let mut ix = lix::Index::none();
        for ((kind, key), ie) in &i.entries {
            let d32 = self.d32_of(ie.digest);
            let len = self.d64.get(&ie.digest).map(|x| x.1).unwrap_or(0);
            ix.upsert(IndexEntry {
                kind: *kind,
                key: key_bytes(*kind, *key),
                parity: ie.parity as u8,
                len,
                digest: d32,
            });
        }
        ix.problems = i.problems;
        ix.lost_entries = i.lost;
        let mut ho = Handover::default();
        let tk = |t: &mut Self, x: Option<(Ver, Digest)>| x.map(|(v, m)| (v, t.m32_of(m)));
        match &i.state {
            PState::None { armed, confirmed } => {
                ix.state = State::None;
                ix.armed = armed.map(rec_bytes);
                ho.confirmed = confirmed.iter().copied().collect();
            }
            PState::Writer(w) => {
                ix.state = State::Writer;
                ix.awaiting_retirement = w.awaiting;
                ho.taken_over = tk(self, w.taken_over);
                ho.paused = w.paused;
            }
            PState::Sealed { w, target, m } => {
                ix.state = State::Sealed;
                ix.awaiting_retirement = w.awaiting;
                ho.taken_over = tk(self, w.taken_over);
                ho.paused = w.paused;
                ix.peer_record = Some(rec_bytes(*target));
                ho.m = Some(self.m32_of(*m));
            }
            PState::Receiving { from, store_failed } => {
                ix.state = State::Receiving;
                ho.receiving_from = *from;
                ho.store_failed = *store_failed;
            }
            PState::Retired { to, m, taken_over } => {
                ix.state = State::Retired;
                ix.peer_record = Some(rec_bytes(*to));
                ho.m = Some(self.m32_of(*m));
                ho.taken_over = tk(self, *taken_over);
            }
        }
        if ho.taken_over.is_some() {
            ho.own_record = Some(rec_bytes(Rec::build(own)));
        }
        ix.ho = ho;
        ix
    }

    // ---------------------------------------------------------------- notes

    pub fn note(&mut self, n: LNote) -> Option<Note> {
        let id = |kind: u8, key: &[u8]| key_of(kind, key).map(|k| (kind, k));
        Some(match n {
            LNote::Unsealed { target, m, cause } => Note::Unsealed {
                target,
                m: self.m64_of(&m),
                cause: cstatus_of(cause),
            },
            LNote::UnsealIntent { target, m } => Note::UnsealIntent {
                target,
                m: self.m64_of(&m),
            },
            LNote::Created => Note::Created,
            LNote::TookOver { from, m } => Note::TookOver {
                from,
                m: self.m64_of(&m),
            },
            LNote::Retired { to, m } => Note::Retired {
                to,
                m: self.m64_of(&m),
            },
            LNote::AwaitingCleared => Note::AwaitingCleared,
            LNote::SealedCorruptSent => Note::SealedCorruptSent,
            LNote::EntryStep(k, kind, key) => Note::EntryStep(k, id(kind, &key)?),
            LNote::Mirrored(kind, key) => Note::Mirrored(id(kind, &key)?),
            LNote::DeleteStep(k, kind, key) => Note::DeleteStep(k, id(kind, &key)?),
            LNote::SweepDone => Note::SweepDone,
            LNote::Listed => Note::Listed,
        })
    }

    // ---------------------------------------------------------------- frames

    /// A model frame as the wire frame build `from` sends to build `to`. A
    /// frame the world damaged in transit (`malformed`) gets trailing bytes:
    /// its header (record, partition, manifest digest) still parses, its
    /// body does not.
    pub fn frame_to_wire(&mut self, from: Ver, _to: Ver, f: &Frame) -> Vec<u8> {
        let p = P();
        let tid = |r: &Rec, pv: Ver| hash::transfer_id(&author_vk(), pv, &rec_bytes(*r));
        let (bytes, malformed) = match f {
            Frame::Chunk {
                rec,
                entries,
                malformed,
            } => {
                let entries = entries.iter().map(|e| self.entry_bytes(e)).collect();
                (
                    wh::Chunk {
                        record: rec_bytes(*rec),
                        partition: p,
                        entries,
                        ext: vec![],
                    }
                    .encode(),
                    *malformed,
                )
            }
            Frame::Ack {
                tid: (pv, r),
                status,
                succ,
                outcomes,
            } => {
                let outcomes = outcomes
                    .iter()
                    .map(|(d, o)| (self.d32_of(*d), outcome_code(*o)))
                    .collect();
                (
                    wh::Ack {
                        transfer_id: tid(r, *pv),
                        chunk_digest: [0; 32],
                        partition: p,
                        status: chunk_code(*status),
                        succ_record: succ.map(rec_bytes),
                        outcomes,
                        ext: vec![],
                    }
                    .encode(),
                    false,
                )
            }
            Frame::Complete {
                rec,
                m,
                digests,
                malformed,
            } => {
                let digests: Vec<[u8; 32]> = digests.iter().map(|d| self.d32_of(*d)).collect();
                let mut c = wh::Complete::new(rec_bytes(*rec), p, digests);
                c.manifest_digest = self.m32_of(*m);
                (c.encode(), *malformed)
            }
            Frame::Abort { rec, m, malformed } => (self.short(types::ABORT, rec, *m), *malformed),
            Frame::Retired { rec, m, malformed } => {
                (self.short(types::RETIRED, rec, *m), *malformed)
            }
            Frame::Query { rec, m } => (self.short(types::QUERY, rec, *m), false),
            Frame::CompleteAck {
                tid: (pv, r),
                m,
                status,
                succ,
                missing,
            } => {
                let missing = missing.iter().map(|d| self.d32_of(*d)).collect();
                (
                    wh::CompleteAck {
                        transfer_id: tid(r, *pv),
                        partition: p,
                        manifest_digest: self.m32_of(*m),
                        status: cstatus_code(*status),
                        succ_record: succ.map(rec_bytes),
                        missing,
                        ext: vec![],
                    }
                    .encode(),
                    false,
                )
            }
        };
        let _ = from;
        let mut b = bytes.expect("a model frame encodes");
        if malformed {
            // damage the body, not the frame: the frame still parses (so
            // the receiver answers it), its body does not
            let f = WFrame::decode(&b).expect("a frame just encoded");
            let (ft, mut body) = (f.frame_type, f.body.to_vec());
            body.extend_from_slice(&[0xBA, 0xD0, 0xBA]);
            b = frame::encode(ft, &body).expect("a damaged body still frames");
        }
        b
    }

    fn short(
        &mut self,
        ft: u8,
        rec: &Rec,
        m: Digest,
    ) -> Result<Vec<u8>, freenet_vault_common::codec::Malformed> {
        wh::Short {
            record: rec_bytes(*rec),
            partition: P(),
            manifest_digest: self.m32_of(m),
            ext: vec![],
        }
        .encode(ft)
    }

    /// A wire frame build `sender` sent, as the model's frame.
    pub fn wire_to_frame(&mut self, _sender: Ver, b: &[u8]) -> Result<Frame, String> {
        self.init_names();
        let f = WFrame::decode(b).map_err(|e| format!("frame: {e:?}"))?;
        Ok(match f.frame_type {
            types::CHUNK => {
                let c = wh::Chunk::decode(f.body).map_err(|e| format!("chunk: {e:?}"))?;
                let mut entries = vec![];
                for e in &c.entries {
                    entries.push(
                        self.entry_of(e)
                            .ok_or("chunk entry not in the model's value space")?,
                    );
                }
                Frame::Chunk {
                    rec: rec_of(&c.record),
                    entries,
                    malformed: false,
                }
            }
            types::ACK => {
                let a = wh::Ack::decode(f.body).map_err(|e| format!("ack: {e:?}"))?;
                Frame::Ack {
                    tid: *self
                        .tids
                        .get(&a.transfer_id)
                        .ok_or("ack for an unknown transfer id")?,
                    status: chunk_status_of(a.status).ok_or("ack status unknown")?,
                    succ: a.succ_record.map(|r| rec_of(&r)),
                    outcomes: a
                        .outcomes
                        .iter()
                        .map(|(d, o)| Some((self.d64_of(d), outcome_of(*o)?)))
                        .collect::<Option<Vec<_>>>()
                        .ok_or("ack outcome code unknown")?,
                }
            }
            types::COMPLETE => {
                let c = wh::Complete::decode(f.body).map_err(|e| format!("complete: {e:?}"))?;
                self.pair_manifest(&c.digests);
                Frame::Complete {
                    rec: rec_of(&c.record),
                    m: self.m64_of(&c.manifest_digest),
                    digests: c.digests.iter().map(|d| self.d64_of(d)).collect(),
                    malformed: false,
                }
            }
            types::ABORT | types::RETIRED | types::QUERY => {
                let s = wh::Short::decode(f.body).map_err(|e| format!("short: {e:?}"))?;
                let rec = rec_of(&s.record);
                let m = self.m64_of(&s.manifest_digest);
                match f.frame_type {
                    types::ABORT => Frame::Abort {
                        rec,
                        m,
                        malformed: false,
                    },
                    types::RETIRED => Frame::Retired {
                        rec,
                        m,
                        malformed: false,
                    },
                    _ => Frame::Query { rec, m },
                }
            }
            types::COMPLETE_ACK => {
                let a =
                    wh::CompleteAck::decode(f.body).map_err(|e| format!("completeack: {e:?}"))?;
                Frame::CompleteAck {
                    tid: *self
                        .tids
                        .get(&a.transfer_id)
                        .ok_or("completeack for an unknown transfer id")?,
                    m: self.m64_of(&a.manifest_digest),
                    status: cstatus_of(a.status).ok_or("completeack status unknown")?,
                    succ: a.succ_record.map(|r| rec_of(&r)),
                    missing: a.missing.iter().map(|d| self.d64_of(d)).collect(),
                }
            }
            t => return Err(format!("frame type {t:#x}")),
        })
    }
}

fn build_kind(n: SName) -> &'static str {
    freenet_vault_model::build::sname_kind(&n)
}

fn chunk_code(s: ChunkStatus) -> u8 {
    match s {
        ChunkStatus::Processed => cs::PROCESSED,
        ChunkStatus::Malformed => cs::MALFORMED,
        ChunkStatus::NotMine => cs::RECORD_NOT_MINE,
        ChunkStatus::Stopped => cs::STOPPED,
        ChunkStatus::HigherBuild => cs::HIGHER_BUILD,
        ChunkStatus::AnotherWriter => cs::ANOTHER_WRITER,
        ChunkStatus::StagingFull => cs::STAGING_FULL,
    }
}

fn chunk_status_of(c: u8) -> Option<ChunkStatus> {
    Some(match c {
        cs::PROCESSED => ChunkStatus::Processed,
        cs::MALFORMED => ChunkStatus::Malformed,
        cs::RECORD_NOT_MINE => ChunkStatus::NotMine,
        cs::STOPPED => ChunkStatus::Stopped,
        cs::HIGHER_BUILD => ChunkStatus::HigherBuild,
        cs::ANOTHER_WRITER => ChunkStatus::AnotherWriter,
        cs::STAGING_FULL => ChunkStatus::StagingFull,
        _ => return None,
    })
}

fn outcome_code(o: Outcome) -> u8 {
    match o {
        Outcome::Stored => outcome::STORED,
        Outcome::Identical => outcome::IDENTICAL,
        Outcome::PolicyDropped => outcome::POLICY_DROPPED,
        Outcome::StagingFull => outcome::STAGING_FULL,
        Outcome::StorageFailure => outcome::STORAGE_FAILURE,
    }
}

fn outcome_of(o: u8) -> Option<Outcome> {
    Some(match o {
        outcome::STORED => Outcome::Stored,
        outcome::IDENTICAL => Outcome::Identical,
        outcome::POLICY_DROPPED => Outcome::PolicyDropped,
        outcome::STAGING_FULL => Outcome::StagingFull,
        outcome::STORAGE_FAILURE => Outcome::StorageFailure,
        _ => return None,
    })
}

pub fn cstatus_code(s: CStatus) -> u8 {
    match s {
        CStatus::Accepted => cstatus::ACCEPTED,
        CStatus::Missing => cstatus::MISSING,
        CStatus::AlreadyWriter => cstatus::ALREADY_WRITER,
        CStatus::Stopped => cstatus::STOPPED,
        CStatus::HigherBuild => cstatus::HIGHER_BUILD,
        CStatus::StorageFailure => cstatus::STORAGE_FAILURE,
        CStatus::Aborted => cstatus::ABORTED,
        CStatus::AnotherWriter => cstatus::ANOTHER_WRITER,
        CStatus::DifferentManifest => cstatus::DIFFERENT_MANIFEST,
        CStatus::Malformed => cstatus::MALFORMED,
        CStatus::Noted => cstatus::NOTED,
        CStatus::NoState => cstatus::NO_STATE,
    }
}

pub fn cstatus_of(c: u8) -> Option<CStatus> {
    CStatus::ALL.iter().copied().find(|s| cstatus_code(*s) == c)
}
