//! freenet-vault: a key-vault delegate library.
//!
//! A domain crate (for example `domains/river`) supplies a [`Domain`] and
//! calls [`process`] from its delegate's `process`. The library owns storage
//! (protocol 4), caller checks (spec 5), and the operations (spec 6,
//! protocol 12.5). The handover between builds (protocol 7) is not built
//! yet: the index keeps an opaque field and the SEALED / RECEIVING / RETIRED
//! states for it, and vault-to-vault frames are ignored.
//!
//! NOT YET PUBLISHED; see the repository README.

pub mod caller;
pub mod consent;
pub mod crypto;
pub mod domain;
pub mod host;
pub mod ops;
#[cfg(test)]
mod ops_tests;
pub mod storage;
pub mod succ;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use domain::{CallerDelegate, Domain, PageContainer};
pub use host::Host;

use freenet_stdlib::prelude::{
    ApplicationMessage, ClientResponse, DelegateError, DelegateMessage, InboundDelegateMsg,
    MessageOrigin, NotificationMessage, OutboundDelegateMsg, UserInputRequest,
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
        // Wake-ups and lifecycle runs only drive the handover, which is not
        // built; the gc above is all there is to do. Everything else is ignored.
        _ => Ok(vec![]),
    }
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
