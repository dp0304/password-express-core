// SPDX-License-Identifier: Apache-2.0
//! Policy signatures (CONTRACTS §7):
//! `Ed25519(device, "aipass:v1:policy:" + b64u(SHA-256(JCS(policy minus signature))))`.

use aipass_crypto::{Ed25519Signer, b64u};

use crate::SignatureError;
use crate::canonical::{CanonicalError, jcs_without_field};
use crate::models::{ApprovalMode, Environment, Policy};

/// b64u(SHA-256(JCS(policy minus signature))).
pub fn policy_digest(policy: &Policy) -> Result<String, CanonicalError> {
    Ok(aipass_crypto::sha256_b64u(jcs_without_field(
        policy,
        "signature",
    )?))
}

/// `aipass:v1:policy:<digest>`.
pub fn signing_message(policy: &Policy) -> Result<String, CanonicalError> {
    Ok(format!("aipass:v1:policy:{}", policy_digest(policy)?))
}

/// Sign in place (sets `signature`; `signed_by` must already name the signer).
pub fn sign_policy(policy: &mut Policy, signer: &dyn Ed25519Signer) -> Result<(), CanonicalError> {
    let msg = signing_message(policy)?;
    policy.signature = b64u::encode(signer.sign(msg.as_bytes()));
    Ok(())
}

/// Verify the policy signature against the `signed_by` device's key.
pub fn verify_policy(policy: &Policy, signer_pk: &[u8; 32]) -> Result<(), SignatureError> {
    let msg = signing_message(policy)?;
    let sig = b64u::decode_array::<64>(&policy.signature).map_err(|_| SignatureError::Malformed)?;
    aipass_crypto::identity::verify(signer_pk, msg.as_bytes(), &sig)
        .map_err(|_| SignatureError::Invalid)
}

/// `auto_approve` is only valid for `rule` mode on a `test` resource whose allowed
/// operations are all read-only.
pub fn auto_approve_allowed(
    policy: &Policy,
    environment: Environment,
    all_operations_read_only: bool,
) -> bool {
    policy.auto_approve
        && policy.approval_mode == ApprovalMode::Rule
        && environment == Environment::Test
        && all_operations_read_only
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::*;
    use crate::models::*;

    pub(crate) fn sample_policy() -> Policy {
        Policy {
            policy_id: PolicyId::parse("pol_01jbz3k6w8a7m2q4t5v9x0y1z6").unwrap(),
            version: 1,
            subject_connection_id: ConnectionId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").unwrap(),
            project_id: ProjectId::parse("proj_01jbz3k6w8a7m2q4t5v9x0y1z3").unwrap(),
            resource_id: ResourceId::parse("res_01jbz3k6w8a7m2q4t5v9x0y1z2").unwrap(),
            executor_id: ExecutorId::parse("exe_01jbz3k6w8a7m2q4t5v9x0y1z7").unwrap(),
            allowed_operations: vec!["postgres.query_view".into()],
            allowed_views: vec!["analytics.subscription_daily".into()],
            allowed_fields: vec!["day".into(), "plan".into(), "subscriptions".into()],
            scope: GrantScope {
                operations: vec!["postgres.query_view".into()],
                postgres: Some(PostgresScope {
                    views: [(
                        "analytics.subscription_daily".to_string(),
                        vec!["day".into(), "plan".into(), "subscriptions".into()],
                    )]
                    .into(),
                }),
                github: None,
                http_api: None,
            },
            limits: Limits::default(),
            grant_ttl_seconds: 900,
            approval_mode: ApprovalMode::Rule,
            auto_approve: true,
            on_control_channel_lost: ControlChannelLostAction::DenyNewOperations,
            output_recipients: vec![
                ConnectionId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").unwrap(),
            ],
            status: PolicyStatus::Active,
            created_at: crate::time::parse_rfc3339("2026-10-30T12:00:00Z").unwrap(),
            signed_by: DeviceId::parse("dev_01jbz3k6w8a7m2q4t5v9x0y1z8").unwrap(),
            signature: String::new(),
        }
    }

    #[test]
    fn sign_verify_tamper() {
        let k = aipass_crypto::Ed25519Keypair::generate();
        let mut p = sample_policy();
        sign_policy(&mut p, &k).unwrap();
        verify_policy(&p, &k.public_key()).unwrap();
        assert!(
            signing_message(&p)
                .unwrap()
                .starts_with("aipass:v1:policy:")
        );
        let mut t = p.clone();
        t.limits.max_rows_per_grant = 1_000_000;
        assert_eq!(
            verify_policy(&t, &k.public_key()),
            Err(SignatureError::Invalid)
        );
        // signature value does not influence the digest
        let mut u = p.clone();
        u.signature = "x".into();
        assert_eq!(policy_digest(&u).unwrap(), policy_digest(&p).unwrap());
    }

    #[test]
    fn auto_approve_rules() {
        let p = sample_policy();
        assert!(auto_approve_allowed(&p, Environment::Test, true));
        assert!(!auto_approve_allowed(&p, Environment::Production, true));
        assert!(!auto_approve_allowed(&p, Environment::Test, false));
        let task = Policy {
            approval_mode: ApprovalMode::Task,
            ..p
        };
        assert!(!auto_approve_allowed(&task, Environment::Test, true));
    }
}
