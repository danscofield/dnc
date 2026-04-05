// Session manager: lifecycle and state machine.

use std::collections::HashMap;
use std::time::Duration;

use thiserror::Error;

use crate::crypto::SessionKey;
use crate::frame::SessionId;
use crate::reliability::{ReassemblyBuffer, RetransmitBuffer};
use crate::socks::ConnectRequest;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("maximum sessions reached ({0})")]
    MaxSessionsReached(usize),

    #[error("session not found")]
    SessionNotFound,
}

// ---------------------------------------------------------------------------
// SessionState
// ---------------------------------------------------------------------------

/// Session state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// SYN sent, waiting for SYN-ACK.
    SynSent,
    /// Data flowing.
    Established,
    /// FIN sent, waiting for acknowledgment.
    FinSent,
    /// Terminal state.
    Closed,
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A single tunnel session.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("upstream_channel", &self.upstream_channel)
            .field("downstream_channel", &self.downstream_channel)
            .field("tx_seq", &self.tx_seq)
            .field("rx_next", &self.rx_next)
            .finish_non_exhaustive()
    }
}

pub struct Session {
    pub id: SessionId,
    pub state: SessionState,
    pub target: ConnectRequest,
    pub upstream_channel: String,
    pub downstream_channel: String,
    pub tx_seq: u32,
    pub rx_next: u32,
    pub session_key: Option<SessionKey>,
    pub retransmit_buf: RetransmitBuffer,
    pub reassembly_buf: ReassemblyBuffer,
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

/// Default maximum number of concurrent sessions.
const DEFAULT_MAX_SESSIONS: usize = 64;

/// Session manager holding all active sessions.
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    max_sessions: usize,
}

impl SessionManager {
    /// Create a new `SessionManager` with the default max sessions (64).
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }

    /// Create a new `SessionManager` with a custom max sessions limit.
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions,
        }
    }

    /// Create a new session for the given target.
    ///
    /// Generates a unique `SessionId`, initialises upstream/downstream channel
    /// names, and sets the session state to `SynSent`.
    pub fn create_session(&mut self, target: ConnectRequest) -> Result<&mut Session, SessionError> {
        if self.sessions.len() >= self.max_sessions {
            return Err(SessionError::MaxSessionsReached(self.max_sessions));
        }

        let id = SessionId::generate();
        let upstream_channel = format!("u-{}", id.as_str());
        let downstream_channel = format!("d-{}", id.as_str());

        let session = Session {
            id: id.clone(),
            state: SessionState::SynSent,
            target,
            upstream_channel,
            downstream_channel,
            tx_seq: 0,
            rx_next: 0,
            session_key: None,
            retransmit_buf: RetransmitBuffer::new(8, 10, Duration::from_secs(2)),
            reassembly_buf: ReassemblyBuffer::new(32),
        };

        self.sessions.insert(id.clone(), session);
        Ok(self.sessions.get_mut(&id).expect("just inserted"))
    }

    /// Get a mutable reference to a session by ID.
    pub fn get_session(&mut self, id: &SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    /// Remove a session by ID.
    pub fn remove_session(&mut self, id: &SessionId) {
        self.sessions.remove(id);
    }

    /// Remove a session by ID and return it.
    pub fn remove_session_return(&mut self, id: &SessionId) -> Option<Session> {
        self.sessions.remove(id)
    }

    /// Insert a session with a specific ID (used by exit node to adopt client-generated IDs).
    pub fn insert_session(&mut self, id: SessionId, session: Session) {
        self.sessions.insert(id, session);
    }

    /// Returns the number of active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get a read-only reference to the sessions map.
    pub fn sessions_ref(&self) -> &HashMap<SessionId, Session> {
        &self.sessions
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socks::{ConnectRequest, TargetAddr};

    fn make_target(port: u16) -> ConnectRequest {
        ConnectRequest {
            target_addr: TargetAddr::Ipv4([127, 0, 0, 1]),
            target_port: port,
        }
    }

    #[test]
    fn create_session_and_verify_fields() {
        let mut mgr = SessionManager::new();
        let session = mgr.create_session(make_target(80)).unwrap();

        assert_eq!(session.state, SessionState::SynSent);
        assert_eq!(session.tx_seq, 0);
        assert_eq!(session.rx_next, 0);
        assert!(session.session_key.is_none());
        assert_eq!(session.target.target_port, 80);

        // Channel names follow the convention
        let id_str = session.id.as_str().to_owned();
        assert_eq!(session.upstream_channel, format!("u-{}", id_str));
        assert_eq!(session.downstream_channel, format!("d-{}", id_str));

        // SessionId is 8 alphanumeric chars
        assert_eq!(id_str.len(), 8);
        assert!(id_str.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn max_sessions_enforcement() {
        let mut mgr = SessionManager::with_max_sessions(2);

        mgr.create_session(make_target(80)).unwrap();
        mgr.create_session(make_target(81)).unwrap();

        let result = mgr.create_session(make_target(82));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SessionError::MaxSessionsReached(2)));
    }

    #[test]
    fn get_session_by_id() {
        let mut mgr = SessionManager::new();
        let id = mgr.create_session(make_target(80)).unwrap().id.clone();

        let session = mgr.get_session(&id);
        assert!(session.is_some());
        assert_eq!(session.unwrap().target.target_port, 80);
    }

    #[test]
    fn get_session_not_found() {
        let mut mgr = SessionManager::new();
        let fake_id = SessionId(*b"ZZZZZZZZ");
        assert!(mgr.get_session(&fake_id).is_none());
    }

    #[test]
    fn remove_session_and_verify_count() {
        let mut mgr = SessionManager::new();
        let id = mgr.create_session(make_target(80)).unwrap().id.clone();
        assert_eq!(mgr.active_count(), 1);

        mgr.remove_session(&id);
        assert_eq!(mgr.active_count(), 0);
        assert!(mgr.get_session(&id).is_none());
    }

    #[test]
    fn create_multiple_sessions() {
        let mut mgr = SessionManager::new();
        let mut ids = Vec::new();

        for port in 80..85 {
            let id = mgr.create_session(make_target(port)).unwrap().id.clone();
            ids.push(id);
        }

        assert_eq!(mgr.active_count(), 5);

        // All sessions are retrievable and have distinct IDs
        for (i, id) in ids.iter().enumerate() {
            let session = mgr.get_session(id).unwrap();
            assert_eq!(session.target.target_port, 80 + i as u16);
        }

        // All IDs are unique
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len());
    }

    #[test]
    fn remove_nonexistent_session_is_noop() {
        let mut mgr = SessionManager::new();
        let fake_id = SessionId(*b"XXXXXXXX");
        mgr.remove_session(&fake_id); // should not panic
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn default_max_sessions_is_64() {
        let mgr = SessionManager::new();
        // Create 64 sessions — should all succeed
        let mut mgr = mgr;
        for i in 0..64 {
            mgr.create_session(make_target(i as u16)).unwrap();
        }
        assert_eq!(mgr.active_count(), 64);

        // 65th should fail
        let result = mgr.create_session(make_target(9999));
        assert!(result.is_err());
    }
}
