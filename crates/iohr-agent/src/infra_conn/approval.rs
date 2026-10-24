//! The approval an apply needs (RFC 0153): pinned to one plan hash, single use.
//!
//! This slice has the interface and a test double fed from the infra run. The real check
//! (a `ClaimRun` against the platform) is slice C4; nothing here calls a server.

/// What the caller presents with an apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The approval's id.
    pub id: String,
    /// The plan hash it pins (`sha256:` and 64 hex).
    pub plan_hash: String,
}

/// Why an approval was not honoured.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Denied(pub String);

/// Decides whether an approval may be spent on a plan hash.
pub trait ApprovalCheck: Send + Sync + std::fmt::Debug {
    /// Spends `approval` for `plan_hash`. Single use: a second call for the same
    /// approval is denied.
    ///
    /// # Errors
    /// The approval is unknown, pinned to another hash, or already spent.
    fn spend(&self, approval: &Approval, plan_hash: &str) -> Result<(), Denied>;
}

/// The default: nothing is approved, so no apply runs.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAll;

impl ApprovalCheck for DenyAll {
    fn spend(&self, _: &Approval, _: &str) -> Result<(), Denied> {
        Err(Denied(
            "no approval source is configured; applies are refused".into(),
        ))
    }
}

/// A test double: approvals are fed in, as the infra run will feed them, and each is
/// spent once. Built only for tests (the `test-approvals` feature), so a release agent
/// cannot be wired to an approval source that anyone in the process can feed.
#[cfg(any(test, feature = "test-approvals"))]
#[derive(Debug, Default)]
pub struct FedApprovals {
    live: std::sync::Mutex<std::collections::BTreeSet<(String, String)>>,
}

#[cfg(any(test, feature = "test-approvals"))]
impl FedApprovals {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one approval, pinned to `plan_hash`.
    pub fn feed(&self, id: &str, plan_hash: &str) {
        let mut g = match self.live.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.insert((id.to_owned(), plan_hash.to_owned()));
    }
}

#[cfg(any(test, feature = "test-approvals"))]
impl ApprovalCheck for FedApprovals {
    fn spend(&self, approval: &Approval, plan_hash: &str) -> Result<(), Denied> {
        if approval.plan_hash != plan_hash {
            return Err(Denied("the approval pins another plan hash".into()));
        }
        let mut g = match self.live.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if g.remove(&(approval.id.clone(), approval.plan_hash.clone())) {
            Ok(())
        } else {
            Err(Denied("the approval is unknown or already spent".into()))
        }
    }
}
