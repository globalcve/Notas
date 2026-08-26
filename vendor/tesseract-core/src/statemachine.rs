//! Volume lifecycle state machine.
//!
//! `UNINITIALIZED -> LOCKED -> UNLOCKING -> ACTIVE_MOUNTED -> UNMOUNTING -> LOCKED`
//!
//! From `ACTIVE_MOUNTED` (and, defensively, from `UNLOCKING`/`UNMOUNTING`),
//! an `EmergencyWipe` edge fires on any wipe trigger and force-returns the
//! volume to `LOCKED` after teardown + zeroization. The state machine is pure:
//! the agent owns the side effects and reports completion via the `*_done`
//! events. The GUI can only submit intents; it cannot force a transition.

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Uninitialized,
    Locked,
    Unlocking,
    ActiveMounted,
    Unmounting,
    /// Transient: tearing down + zeroizing after a wipe trigger.
    EmergencyWiping,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Uninitialized => "UNINITIALIZED",
            State::Locked => "LOCKED",
            State::Unlocking => "UNLOCKING",
            State::ActiveMounted => "ACTIVE_MOUNTED",
            State::Unmounting => "UNMOUNTING",
            State::EmergencyWiping => "EMERGENCY_WIPING",
        }
    }
}

/// Why an emergency wipe fired (logged + surfaced in the GUI, never secret).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WipeTrigger {
    PrepareForSleep,
    IdleTimeout,
    SessionLock,
    Logout,
    FastUserSwitch,
    SocketEof,
    Tamper,
    Panic,
}

impl WipeTrigger {
    pub fn name(self) -> &'static str {
        match self {
            WipeTrigger::PrepareForSleep => "prepare-for-sleep",
            WipeTrigger::IdleTimeout => "idle-timeout",
            WipeTrigger::SessionLock => "session-lock",
            WipeTrigger::Logout => "logout",
            WipeTrigger::FastUserSwitch => "fast-user-switch",
            WipeTrigger::SocketEof => "socket-eof",
            WipeTrigger::Tamper => "tamper",
            WipeTrigger::Panic => "panic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Volume header created/discovered on disk.
    Initialized,
    /// User asked to unlock (credentials arrived).
    UnlockRequested,
    /// Agent finished KDF + slot open + data plane setup successfully.
    UnlockSucceeded,
    /// Any unlock step failed (timing-flat generic failure).
    UnlockFailed,
    /// User asked to lock/unmount.
    LockRequested,
    /// Teardown finished cleanly.
    UnmountDone,
    /// A wipe trigger fired.
    Wipe(WipeTrigger),
    /// Wipe teardown + zeroization finished.
    WipeDone,
}

/// The transition function. Returns the next state or an error for an
/// illegal event in the current state (illegal events are protocol errors
/// from the GUI/CLI and are rejected, never panics).
pub fn next(state: State, event: Event) -> Result<State> {
    use Event::*;
    use State::*;
    let bad = |action: &'static str| {
        Err(Error::BadTransition {
            state: state.name(),
            action,
        })
    };
    match (state, event) {
        (Uninitialized, Initialized) => Ok(Locked),
        (Uninitialized, _) => bad("only initialization is valid"),

        (Locked, UnlockRequested) => Ok(Unlocking),
        // Wipe while locked is a no-op safety edge: stay locked.
        (Locked, Wipe(_)) => Ok(Locked),
        (Locked, _) => bad("volume is locked"),

        (Unlocking, UnlockSucceeded) => Ok(ActiveMounted),
        (Unlocking, UnlockFailed) => Ok(Locked),
        // A trigger during unlock scrubs temporaries and locks.
        (Unlocking, Wipe(_)) => Ok(EmergencyWiping),
        (Unlocking, _) => bad("unlock in progress"),

        (ActiveMounted, LockRequested) => Ok(Unmounting),
        (ActiveMounted, Wipe(_)) => Ok(EmergencyWiping),
        (ActiveMounted, _) => bad("volume is mounted"),

        (Unmounting, UnmountDone) => Ok(Locked),
        // Failure to unmount cleanly escalates to a forced wipe.
        (Unmounting, Wipe(_)) => Ok(EmergencyWiping),
        (Unmounting, _) => bad("unmount in progress"),

        (EmergencyWiping, WipeDone) => Ok(Locked),
        (EmergencyWiping, Wipe(_)) => Ok(EmergencyWiping),
        (EmergencyWiping, _) => bad("emergency wipe in progress"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Event::*;
    use State::*;

    const TRIGGERS: [WipeTrigger; 8] = [
        WipeTrigger::PrepareForSleep,
        WipeTrigger::IdleTimeout,
        WipeTrigger::SessionLock,
        WipeTrigger::Logout,
        WipeTrigger::FastUserSwitch,
        WipeTrigger::SocketEof,
        WipeTrigger::Tamper,
        WipeTrigger::Panic,
    ];

    #[test]
    fn happy_path() {
        let mut s = Uninitialized;
        for (ev, want) in [
            (Initialized, Locked),
            (UnlockRequested, Unlocking),
            (UnlockSucceeded, ActiveMounted),
            (LockRequested, Unmounting),
            (UnmountDone, Locked),
        ] {
            s = next(s, ev).unwrap();
            assert_eq!(s, want);
        }
    }

    #[test]
    fn failed_unlock_returns_to_locked() {
        let s = next(Unlocking, UnlockFailed).unwrap();
        assert_eq!(s, Locked);
    }

    #[test]
    fn every_trigger_fires_emergency_wipe_from_active() {
        for t in TRIGGERS {
            let s = next(ActiveMounted, Wipe(t)).unwrap();
            assert_eq!(s, EmergencyWiping, "{:?}", t);
            assert_eq!(next(s, WipeDone).unwrap(), Locked);
        }
    }

    #[test]
    fn wipe_during_unlock_and_unmount() {
        for t in TRIGGERS {
            assert_eq!(next(Unlocking, Wipe(t)).unwrap(), EmergencyWiping);
            assert_eq!(next(Unmounting, Wipe(t)).unwrap(), EmergencyWiping);
        }
    }

    #[test]
    fn wipe_when_locked_is_noop() {
        for t in TRIGGERS {
            assert_eq!(next(Locked, Wipe(t)).unwrap(), Locked);
        }
    }

    /// Exhaustive: every (state, event) pair either transitions or returns a
    /// BadTransition error — never panics, never silently ignores.
    #[test]
    fn exhaustive_no_panics() {
        let states = [
            Uninitialized,
            Locked,
            Unlocking,
            ActiveMounted,
            Unmounting,
            EmergencyWiping,
        ];
        let events = [
            Initialized,
            UnlockRequested,
            UnlockSucceeded,
            UnlockFailed,
            LockRequested,
            UnmountDone,
            Wipe(WipeTrigger::Panic),
            WipeDone,
        ];
        for s in states {
            for e in events {
                let _ = next(s, e); // must not panic
            }
        }
    }

    /// The GUI cannot force a mount: from Locked, UnlockSucceeded (an
    /// agent-internal event) is invalid without UnlockRequested first, and
    /// even then the agent generates it, not the client.
    #[test]
    fn cannot_skip_unlocking() {
        assert!(next(Locked, UnlockSucceeded).is_err());
        assert!(next(Locked, UnmountDone).is_err());
        assert!(next(Uninitialized, UnlockRequested).is_err());
    }
}
