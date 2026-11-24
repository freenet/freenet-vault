//! Test-visible counters, transition notes and mutation switches.
//!
//! With the `trace` feature off (every real build) every item here is a
//! no-op the compiler removes: `hit!` expands to nothing, [`note`] is empty
//! and [`mutant`] is always false.
//!
//! With `trace` on, the conformance harness (`crates/freenet-vault-conformance`)
//! installs a sink and reads back the same coverage counters, by the same
//! names, that the simulation model (`crates/freenet-vault-model`) counts, and
//! the transitions the model's invariant checker needs (`Note`). It can also
//! switch on one deliberately broken variant of a guard at a time (15.5
//! mutation check), named as the model names them.

/// A transition the invariant checker needs to see (the model's `Note`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    Unsealed {
        target: u32,
        m: [u8; 32],
        cause: u8,
    },
    UnsealIntent {
        target: u32,
        m: [u8; 32],
    },
    Created,
    TookOver {
        from: u32,
        m: [u8; 32],
    },
    Retired {
        to: u32,
        m: [u8; 32],
    },
    AwaitingCleared,
    SealedCorruptSent,
    /// Step k of an entry write of (kind, key) is about to happen (4.2).
    EntryStep(u8, u8, Vec<u8>),
    /// Step 4 of an entry write landed.
    Mirrored(u8, Vec<u8>),
    /// Step k of a Delete of (kind, key) is about to happen (4.2).
    DeleteStep(u8, u8, Vec<u8>),
    SweepDone,
    Listed,
}

/// The deliberately broken variants the library implements (15.5), by the
/// model's names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutant {
    RetiredBeforeUnlist,
    NeverUnlist,
    RelistRetired,
    PartsBeforeIndex,
    CreateWhileStopped,
    NoState0x0BWithoutStoring,
    MirrorBeforeCommit,
    NoStep1,
    DeleteCommitBeforeMirrorAbsent,
    SweepUncheckedDigest,
    DirectReadSingleCopy,
    DirectReadChooses,
    DirectReadIgnoresEflagsOrKey,
    DirectReadAbsent,
    ListNoneOrReceiving,
    AnswerBeforeListing,
    MalformedListedIsNone,
    MalformedUnlistedIsLost,
    WriteWithoutRemove,
    DirectReadDespiteSuccessor,
    // Base mutants of 15.5 beyond the model's list.
    UnsealOnHigherRecord,
    StoppedBeforeTakenOver,
    ClearAwaitingWithoutAnswer,
    CopyWhileAwaiting,
    GcWithoutIndexCheck,
    CreateWithUnansweredProbe,
    IgnoreQueryAnswer,
    QueryRetiredToOther,
    MissingAsAccepted,
    WithdrawalLiftsBar,
}

#[cfg(feature = "trace")]
mod imp {
    use super::{Mutant, Note};
    use std::cell::{Cell, RefCell};

    pub enum Ev {
        Hit(String),
        Note(Note),
    }

    type Sink = Box<dyn FnMut(Ev)>;

    thread_local! {
        static SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
        static MUTANT: Cell<Option<Mutant>> = const { Cell::new(None) };
    }

    /// Installs (or with `None` removes) the event sink for this thread.
    pub fn set_sink(s: Option<Sink>) {
        SINK.with(|c| *c.borrow_mut() = s);
    }

    pub fn set_mutant(m: Option<Mutant>) {
        MUTANT.with(|c| c.set(m));
    }

    pub fn emit(e: Ev) {
        SINK.with(|c| {
            if let Some(f) = c.borrow_mut().as_mut() {
                f(e)
            }
        });
    }

    pub fn note(n: Note) {
        emit(Ev::Note(n));
    }

    pub fn mutant(m: Mutant) -> bool {
        MUTANT.with(|c| c.get()) == Some(m)
    }
}

#[cfg(feature = "trace")]
pub use imp::{emit, mutant, note, set_mutant, set_sink, Ev};

#[cfg(not(feature = "trace"))]
#[inline(always)]
pub fn note(_n: Note) {}

#[cfg(not(feature = "trace"))]
#[inline(always)]
pub fn mutant(_m: Mutant) -> bool {
    false
}

/// Counts a coverage counter by the model's name. Arguments after the first
/// are formatted only when the `trace` feature is on.
#[macro_export]
macro_rules! hit {
    ($($arg:tt)*) => {{
        #[cfg(feature = "trace")]
        {
            $crate::trace::emit($crate::trace::Ev::Hit(format!($($arg)*)));
        }
    }};
}
