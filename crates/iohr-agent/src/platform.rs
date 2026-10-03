//! Calls to the platform made with a person's token handed over by iohr (`init`): check
//! that every bound domain is verified in the account, and create the enrollment.

use serde::Deserialize;
use serde_json::json;
use url::Url;
use zeroize::Zeroizing;

use crate::enroll::{problem, without_url};
use crate::error::{Error, Result};

#[derive(Debug, Deserialize)]
struct DomainList {
    #[serde(default)]
    domains: Vec<Domain>,
}

#[derive(Debug, Deserialize)]
struct Domain {
    domain: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct EnrollmentCreated {
    enrollment_id: String,
    token: String,
    #[serde(default)]
    expires_at: Option<String>,
}

/// A new enrollment: its id, its one-time token, and when the token expires.
#[derive(Debug)]
pub struct NewEnrollment {
    /// The enrollment.
    pub enrollment_id: String,
    /// The one-time token.
    pub token: Zeroizing<String>,
    /// Expiry, RFC 3339.
    pub expires_at: Option<String>,
}

fn check_account(account: &str) -> Result<()> {
    if account.is_empty()
        || account.len() > 64
        || !account
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::Config(format!("{account:?} is not an account id")));
    }
    Ok(())
}

/// Fails unless every domain is covered by a verified domain of the account
/// (RFC 0030: a verified domain covers itself and every name under it).
///
/// # Errors
/// The first uncovered domain, or a platform error.
pub async fn check_domains(
    http: &reqwest::Client,
    api: &Url,
    token: &str,
    account: &str,
    domains: &[String],
) -> Result<()> {
    check_account(account)?;
    let url = api
        .join(&format!("v1/accounts/orgs/{account}/domains"))
        .map_err(|e| Error::Platform(e.to_string()))?;
    let resp = http
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| Error::Platform(format!("could not reach {api}: {}", without_url(&e))))?;
    if !resp.status().is_success() {
        return Err(Error::Platform(problem(resp).await));
    }
    let list: DomainList = resp
        .json()
        .await
        .map_err(|e| Error::Platform(format!("unexpected answer: {}", without_url(&e))))?;
    for d in domains {
        let covered = list.domains.iter().any(|v| {
            v.status == "verified" && (d == &v.domain || d.ends_with(&format!(".{}", v.domain)))
        });
        if !covered {
            return Err(Error::Platform(format!(
                "{d} is not inside a verified domain of account {account}; prove it first with `iohr domains add {d}`"
            )));
        }
    }
    Ok(())
}

/// Creates an enrollment and returns its one-time token.
///
/// # Errors
/// When the platform refuses.
pub async fn create_enrollment(
    http: &reqwest::Client,
    api: &Url,
    token: &str,
    account: &str,
    environment: &str,
    domains: &[String],
    name: &str,
) -> Result<NewEnrollment> {
    check_account(account)?;
    let url = api
        .join(&format!("v1/accounts/orgs/{account}/agents/enrollments"))
        .map_err(|e| Error::Platform(e.to_string()))?;
    let resp = http
        .post(url)
        .bearer_auth(token)
        .json(&json!({"environment": environment, "domains": domains, "name": name}))
        .send()
        .await
        .map_err(|e| Error::Platform(format!("could not reach {api}: {}", without_url(&e))))?;
    if !resp.status().is_success() {
        return Err(Error::Platform(problem(resp).await));
    }
    let c: EnrollmentCreated = resp
        .json()
        .await
        .map_err(|e| Error::Platform(format!("unexpected answer: {}", without_url(&e))))?;
    Ok(NewEnrollment {
        enrollment_id: c.enrollment_id,
        token: Zeroizing::new(c.token),
        expires_at: c.expires_at,
    })
}
