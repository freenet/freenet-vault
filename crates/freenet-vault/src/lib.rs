//! freenet-vault: a key-vault delegate library.
//!
//! A domain crate (for example `domains/river`) supplies a [`Domain`] and
//! calls [`process`] from its delegate's `process`. The library owns storage
//! (protocol 4), caller checks (spec 5), the operations (spec 6, protocol
//! 12.5), and the handover between builds (protocol 3, 5, 6 and 7, in
//! `handover`).
//!
//! NOT YET PUBLISHED; see the repository README.

pub mod caller;
pub mod consent;
pub mod crypto;
pub mod ctx;
pub mod domain;
pub mod handover;
pub mod host;
pub mod limits;
pub mod ops;
#[cfg(test)]
mod ops_tests;
pub mod storage;
pub mod succ;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod trace;

pub use domain::{CallerDelegate, Domain, PageContainer};
pub use host::Host;

use freenet_stdlib::prelude::{
    ApplicationMessage, ClientResponse, CodeHash, DelegateError, DelegateKey, DelegateMessage,
    InboundDelegateMsg, LifecycleEvent, MessageOrigin, NotificationMessage, OutboundDelegateMsg,
    UserInputRequest,
};
use ops::Outcome;

/// The vault's `DelegateInterface::process`, over any [`Host`].
///
/// Every vault build is registered with empty parameters (D1); any other
/// parameters fail every call.
pub fn process<H: Host>(
    domain: &Domain,
    host: &mut H,
    parameters: &[u8],
    origin: Option<&MessageOrigin>,
    message: InboundDelegateMsg,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    if !parameters.is_empty() {
        return Err(DelegateError::Other(
            "a vault is registered with empty parameters".into(),
        ));
    }
    // One latch for the whole call: after a failed write nothing more is
    // written or removed, however many stores the call opens.
    let mut latch = host::WriteLatch::new(host);
    let host = &mut latch;
    // The listing rules (4.2): a RETIRED build still listed unlists first; a
    // valid WRITER or SEALED index that is not listed is listed first (the
    // catch-all, G3). If that write or its read-back fails the call answers
    // nothing (the sender or client retries).
    if storage::fix_listing(host, &domain.partition()).is_err() {
        return Ok(vec![]);
    }
    // A non-empty vault:gc is processed at the start of every call (4.2).
    if let Ok(mut store) = storage::Store::open(host, domain.partition()) {
        store.process_gc();
    }
    match message {
        InboundDelegateMsg::ApplicationMessage(m) => {
            if m.processed {
                return Err(DelegateError::Other("message already processed".into()));
            }
            let outcome = match origin {
                Some(MessageOrigin::WebApp(id)) => {
                    let id: [u8; 32] = id.as_bytes().try_into().expect("32-byte instance id");
                    let poke = freenet_vault_common::frame::Frame::decode(&m.payload)
                        .ok()
                        .filter(|f| f.frame_type == freenet_vault_common::frame::types::POKE)
                        .map(|f| f.body.to_vec());
                    if let Some(body) = poke {
                        let out = handover::poke(domain, host, domain.is_own_page(&id), &body);
                        let mut msgs = hops(out.hops);
                        if let Some(r) = out.reply {
                            msgs.insert(
                                0,
                                OutboundDelegateMsg::ApplicationMessage(
                                    ApplicationMessage::new(r).processed(true),
                                ),
                            );
                        }
                        return Ok(msgs);
                    }
                    ops::handle_page(domain, host, &id, &m.payload)
                }
                // No attested caller (protocol 6): nothing, and say why.
                None => refuse(
                    &m.payload,
                    freenet_vault_common::status::refused::ORIGIN_REQUIRED,
                ),
                // An application message never carries a delegate's origin.
                Some(_) => refuse(
                    &m.payload,
                    freenet_vault_common::status::refused::CALLER_NOT_AUTHORIZED,
                ),
            };
            Ok(to_page(outcome))
        }
        InboundDelegateMsg::DelegateMessage(dm) => {
            let Some(MessageOrigin::Delegate(key)) = origin else {
                return Ok(vec![]);
            };
            if key.bytes() != dm.sender.bytes() {
                return Ok(vec![]);
            }
            let k: [u8; 32] = key.bytes().try_into().expect("32-byte delegate key");
            let handover_frame = freenet_vault_common::frame::Frame::decode(&dm.payload)
                .is_ok_and(|f| handover::is_handover_frame(f.frame_type));
            if handover_frame {
                let out = handover::hop(domain, host, &k, &dm.payload);
                let mut msgs = hops(out.hops);
                if let Some(r) = out.reply {
                    msgs.insert(
                        0,
                        OutboundDelegateMsg::SendDelegateMessage(DelegateMessage::new(
                            dm.sender.clone(),
                            dm.sender.clone(),
                            r,
                        )),
                    );
                }
                return Ok(msgs);
            }
            match ops::handle_delegate(domain, host, &k, &dm.payload) {
                // One reply to the caller. The core sets `sender` to this
                // delegate's key (freenet-core #6340).
                Outcome::Reply(bytes) => Ok(vec![OutboundDelegateMsg::SendDelegateMessage(
                    DelegateMessage::new(dm.sender.clone(), dm.sender.clone(), bytes),
                )]),
                Outcome::Prompt { .. } | Outcome::Nothing => Ok(vec![]),
            }
        }
        InboundDelegateMsg::UserResponse(r) => {
            let Some(MessageOrigin::WebApp(id)) = origin else {
                return Err(DelegateError::Other("answer without a page origin".into()));
            };
            let id: [u8; 32] = id.as_bytes().try_into().expect("32-byte instance id");
            match ops::export_answer(domain, host, &id, r.request_id, &r.response) {
                Some(outcome) => Ok(to_page(outcome)),
                None => Err(DelegateError::Other("answer to an unknown prompt".into())),
            }
        }
        // Wake-ups and NodeStarted drive the handover (6, 7.7).
        InboundDelegateMsg::WakeupFired { tag } if tag == WAKEUP_TAG => {
            Ok(hops(handover::wakeup(domain, host)))
        }
        InboundDelegateMsg::Lifecycle(LifecycleEvent::NodeStarted { .. }) => {
            Ok(hops(handover::wakeup(domain, host)))
        }
        // Everything else is ignored.
        _ => Ok(vec![]),
    }
}

/// The wake-up tag a domain declares in its delegate manifest (6).
pub const WAKEUP_TAG: &[u8] = b"handover";

/// Hops to other vault builds. The node sets the sender (freenet-core #6340);
/// the target is the build whose code hash the hop names, with empty
/// parameters.
fn hops(h: handover::Hops) -> Vec<OutboundDelegateMsg> {
    h.into_iter()
        .map(|(code, frame)| {
            let key = DelegateKey::new(
                freenet_vault_common::hash::delegate_key_empty_params(&code),
                CodeHash::new(code),
            );
            OutboundDelegateMsg::SendDelegateMessage(DelegateMessage::new(key.clone(), key, frame))
        })
        .collect()
}

/// A refusal for a message whose frame may not parse.
fn refuse(payload: &[u8], reason: u8) -> Outcome {
    use freenet_vault_common::frame::Frame;
    let rid = match Frame::decode(payload) {
        Ok(f)
            if freenet_vault_common::ops::is_operation(f.frame_type)
                || f.frame_type == freenet_vault_common::frame::types::SUBMIT_RECORD =>
        {
            freenet_vault_common::ops::Request::peek_request_id(f.body)
        }
        _ => 0,
    };
    // A Refused frame has a fixed shape and cannot fail to encode.
    Outcome::Reply(
        freenet_vault_common::status::Status::Refused {
            request_id: rid,
            reason,
        }
        .encode()
        .unwrap_or_default(),
    )
}

fn to_page(outcome: Outcome) -> Vec<OutboundDelegateMsg> {
    match outcome {
        Outcome::Reply(bytes) => vec![OutboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(bytes).processed(true),
        )],
        Outcome::Prompt { prompt_id, text } => {
            let message = NotificationMessage::try_from(&serde_json::Value::String(text))
                .expect("a JSON string always encodes");
            vec![OutboundDelegateMsg::RequestUserInput(UserInputRequest {
                request_id: prompt_id,
                message,
                responses: vec![
                    ClientResponse::new(consent::ALLOW.to_vec()),
                    ClientResponse::new(consent::DENY.to_vec()),
                ],
            })]
        }
        Outcome::Nothing => vec![],
    }
}
