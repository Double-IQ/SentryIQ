//! Shared TUF trust-root verification core for the iOS and Android companions.
//!
//! Prototype only. The initial root must be pinned out-of-band; this function
//! checks its exact SHA-256 before validating its self-signature threshold and
//! every sequential root rotation.

uniffi::setup_scaffolding!();

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tuffet::jiff::Timestamp;
use tuffet::pouf::Json;
use tuffet::trusted::{TargetSearch, TrustedMetadata};

const MAX_ROOT_BYTES: usize = 5 * 1024 * 1024;
const MAX_ROOT_ROTATIONS: usize = 64;
const MAX_ROOT_CHAIN_BYTES: usize = 20 * 1024 * 1024;
const MAX_DELEGATED_METADATA_BYTES: usize = 20 * 1024 * 1024;
const MAX_DELEGATED_ROLES: usize = 32;
const MAX_TARGET_PATH_BYTES: usize = 4096;

/// Verifies a pinned initial TUF root and a sequence of sequential root updates.
///
/// Returns the number of accepted rotations. Returns -1 for any invalid input,
/// pin mismatch, invalid root, signature-threshold failure, skipped version,
/// or invalid rotation chain. Persist the final candidate only after success.
///
/// This does not fetch metadata, verify timestamp/snapshot/targets, persist
/// rollback state, or establish the out-of-band initial pin.
#[uniffi::export]
pub fn verify_tuf_root_rotation_chain(
    initial_root: Vec<u8>,
    expected_initial_root_sha256: Vec<u8>,
    candidate_roots: Vec<Vec<u8>>,
    reference_time_unix_seconds: i64,
) -> i32 {
    if initial_root.is_empty()
        || initial_root.len() > MAX_ROOT_BYTES
        || expected_initial_root_sha256.len() != 32
        || candidate_roots.len() > MAX_ROOT_ROTATIONS
        || candidate_roots
            .iter()
            .any(|root| root.is_empty() || root.len() > MAX_ROOT_BYTES)
        || !within_byte_budget(candidate_roots.iter().map(Vec::as_slice), MAX_ROOT_CHAIN_BYTES)
    {
        return -1;
    }

    let digest = Sha256::digest(&initial_root);
    if digest
        .as_slice()
        .ct_eq(expected_initial_root_sha256.as_slice())
        .unwrap_u8()
        != 1
    {
        return -1;
    }

    let reference_time = match Timestamp::from_second(reference_time_unix_seconds) {
        Ok(value) => value,
        Err(_) => return -1,
    };

    let mut trusted = match TrustedMetadata::<Json>::new(&initial_root, reference_time) {
        Ok(value) => value,
        Err(_) => return -1,
    };

    for candidate in &candidate_roots {
        if trusted.update_root(candidate).is_err() {
            return -1;
        }
    }

    candidate_roots.len() as i32
}

/// Verifies a complete top-level TUF metadata refresh without performing I/O.
///
/// Cached timestamp, snapshot, and targets metadata must be supplied together
/// or all omitted for first bootstrap. When present, they are loaded as the
/// rollback baseline before the new metadata is accepted. Returns false on any
/// parse, expiry, signature, version, hash, or cache-consistency failure.
///
/// Delegated targets, network transport, persistent storage, and atomic commit
/// remain the caller's responsibility.
#[uniffi::export]
pub fn verify_tuf_metadata_refresh(
    initial_root: Vec<u8>,
    expected_initial_root_sha256: Vec<u8>,
    candidate_roots: Vec<Vec<u8>>,
    cached_timestamp: Option<Vec<u8>>,
    cached_snapshot: Option<Vec<u8>>,
    cached_targets: Option<Vec<u8>>,
    new_timestamp: Vec<u8>,
    new_snapshot: Vec<u8>,
    new_targets: Vec<u8>,
    reference_time_unix_seconds: i64,
) -> bool {
    let cached_count = [
        cached_timestamp.is_some(),
        cached_snapshot.is_some(),
        cached_targets.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if cached_count != 0 && cached_count != 3 {
        return false;
    }
    if cached_timestamp.as_ref().map_or(false, |bytes| bytes.is_empty() || bytes.len() > 1024 * 1024)
        || cached_snapshot.as_ref().map_or(false, |bytes| bytes.is_empty() || bytes.len() > MAX_ROOT_BYTES)
        || cached_targets.as_ref().map_or(false, |bytes| bytes.is_empty() || bytes.len() > MAX_ROOT_BYTES)
    {
        return false;
    }
    if new_timestamp.is_empty()
        || new_timestamp.len() > 1024 * 1024
        || new_snapshot.is_empty()
        || new_snapshot.len() > MAX_ROOT_BYTES
        || new_targets.is_empty()
        || new_targets.len() > MAX_ROOT_BYTES
    {
        return false;
    }

    if initial_root.is_empty()
        || initial_root.len() > MAX_ROOT_BYTES
        || expected_initial_root_sha256.len() != 32
        || candidate_roots.len() > MAX_ROOT_ROTATIONS
        || candidate_roots
            .iter()
            .any(|root| root.is_empty() || root.len() > MAX_ROOT_BYTES)
    {
        return false;
    }

    let digest = Sha256::digest(&initial_root);
    if digest
        .as_slice()
        .ct_eq(expected_initial_root_sha256.as_slice())
        .unwrap_u8()
        != 1
    {
        return false;
    }

    let reference_time = match Timestamp::from_second(reference_time_unix_seconds) {
        Ok(value) => value,
        Err(_) => return false,
    };

    let mut trusted = match TrustedMetadata::<Json>::new(&initial_root, reference_time) {
        Ok(value) => value,
        Err(_) => return false,
    };

    for candidate in &candidate_roots {
        if trusted.update_root(candidate).is_err() {
            return false;
        }
    }

    if let (Some(timestamp), Some(snapshot), Some(targets)) =
        (cached_timestamp, cached_snapshot, cached_targets)
    {
        if trusted.load_cached_timestamp(&timestamp).is_err()
            || trusted.load_cached_snapshot(&snapshot).is_err()
            || trusted.update_targets(&targets).is_err()
        {
            return false;
        }
    }

    trusted.update_timestamp(&new_timestamp).is_ok()
        && trusted.update_snapshot(&new_snapshot).is_ok()
        && trusted.update_targets(&new_targets).is_ok()
}

/// Verifies that a target is authorised by the top-level targets role or by a
/// complete, signature-valid delegated-target chain.
///
/// The caller supplies delegated role metadata by role name. The resolver
/// follows TUF's pre-order depth-first delegation rules, including path
/// matching, priority, terminating delegations, cycle handling, and a strict
/// maximum number of visited roles. Every delegated metadata object is checked
/// by Tuffet against the delegator that authorises that exact step.
///
/// This verifies target authorisation metadata only. It does not download the
/// target bytes or verify their length/hash; use the trusted target description
/// in the subsequent download-and-verify stage.
#[uniffi::export]
pub fn verify_tuf_target_delegation(
    initial_root: Vec<u8>,
    expected_initial_root_sha256: Vec<u8>,
    candidate_roots: Vec<Vec<u8>>,
    cached_timestamp: Option<Vec<u8>>,
    cached_snapshot: Option<Vec<u8>>,
    cached_targets: Option<Vec<u8>>,
    new_timestamp: Vec<u8>,
    new_snapshot: Vec<u8>,
    new_targets: Vec<u8>,
    delegated_roles: Vec<String>,
    delegated_metadata: Vec<Vec<u8>>,
    target_path: String,
    reference_time_unix_seconds: i64,
) -> bool {
    let cached_count = [
        cached_timestamp.is_some(),
        cached_snapshot.is_some(),
        cached_targets.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if cached_count != 0 && cached_count != 3 {
        return false;
    }
    if cached_timestamp.as_ref().map_or(false, |bytes| bytes.is_empty() || bytes.len() > 1024 * 1024)
        || cached_snapshot.as_ref().map_or(false, |bytes| bytes.is_empty() || bytes.len() > MAX_ROOT_BYTES)
        || cached_targets.as_ref().map_or(false, |bytes| bytes.is_empty() || bytes.len() > MAX_ROOT_BYTES)
    {
        return false;
    }

    if !is_safe_target_path(&target_path)
        || delegated_roles.len() != delegated_metadata.len()
        || delegated_roles.len() > MAX_DELEGATED_ROLES
        || delegated_roles
            .iter()
            .any(|role| role.is_empty() || role.len() > 255 || role.chars().any(char::is_control))
        || delegated_metadata
            .iter()
            .any(|metadata| metadata.is_empty() || metadata.len() > MAX_ROOT_BYTES)
        || !within_byte_budget(delegated_metadata.iter().map(Vec::as_slice), MAX_DELEGATED_METADATA_BYTES)
    {
        return false;
    }

    let mut delegated = HashMap::with_capacity(delegated_roles.len());
    let mut seen_roles = HashSet::with_capacity(delegated_roles.len());
    for (role, metadata) in delegated_roles.into_iter().zip(delegated_metadata) {
        if !seen_roles.insert(role.clone()) {
            return false;
        }
        delegated.insert(role, metadata);
    }

    if initial_root.is_empty()
        || initial_root.len() > MAX_ROOT_BYTES
        || expected_initial_root_sha256.len() != 32
        || candidate_roots.len() > MAX_ROOT_ROTATIONS
        || candidate_roots
            .iter()
            .any(|root| root.is_empty() || root.len() > MAX_ROOT_BYTES)
        || !within_byte_budget(candidate_roots.iter().map(Vec::as_slice), MAX_ROOT_CHAIN_BYTES)
        || new_timestamp.is_empty()
        || new_timestamp.len() > 1024 * 1024
        || new_snapshot.is_empty()
        || new_snapshot.len() > MAX_ROOT_BYTES
        || new_targets.is_empty()
        || new_targets.len() > MAX_ROOT_BYTES
    {
        return false;
    }

    let digest = Sha256::digest(&initial_root);
    if digest
        .as_slice()
        .ct_eq(expected_initial_root_sha256.as_slice())
        .unwrap_u8()
        != 1
    {
        return false;
    }

    let reference_time = match Timestamp::from_second(reference_time_unix_seconds) {
        Ok(value) => value,
        Err(_) => return false,
    };

    let mut trusted = match TrustedMetadata::<Json>::new(&initial_root, reference_time) {
        Ok(value) => value,
        Err(_) => return false,
    };

    for candidate in &candidate_roots {
        if trusted.update_root(candidate).is_err() {
            return false;
        }
    }

    if let (Some(timestamp), Some(snapshot), Some(targets)) =
        (cached_timestamp, cached_snapshot, cached_targets)
    {
        if trusted.load_cached_timestamp(&timestamp).is_err()
            || trusted.load_cached_snapshot(&snapshot).is_err()
            || trusted.update_targets(&targets).is_err()
        {
            return false;
        }
    }

    if trusted.update_timestamp(&new_timestamp).is_err()
        || trusted.update_snapshot(&new_snapshot).is_err()
        || trusted.update_targets(&new_targets).is_err()
    {
        return false;
    }

    let mut search = TargetSearch::new(target_path, MAX_DELEGATED_ROLES + 1);
    while let Some(step) = search.next_step() {
        let metadata = if step.role == "targets" {
            trusted.targets()
        } else {
            let Some(raw_metadata) = delegated.get(&step.role) else {
                // Missing metadata for a path-matching delegation is an
                // incomplete trust chain, not evidence that the target is absent.
                return false;
            };
            if trusted
                .update_delegated_targets(raw_metadata, &step.role, &step.delegator)
                .is_err()
            {
                return false;
            }
            trusted.targets_role(&step.role)
        };

        let Some(metadata) = metadata else {
            return false;
        };
        if search.visit(&step, metadata.signed()).is_some() {
            return true;
        }
    }

    false
}

fn within_byte_budget<'a>(items: impl Iterator<Item = &'a [u8]>, limit: usize) -> bool {
    items
        .try_fold(0usize, |total, item| total.checked_add(item.len()))
        .is_some_and(|total| total <= limit)
}

fn is_safe_target_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > MAX_TARGET_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return false;
    }

    path.split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tuffet::crypto::HashAlgorithm;
    use tuffet::metadata::{DelegatedRole, Delegations, TargetFile, Targets};

    #[test]
    fn rejects_empty_initial_root() {
        assert_eq!(
            verify_tuf_root_rotation_chain(vec![], vec![0; 32], vec![], 1_700_000_000),
            -1
        );
    }

    #[test]
    fn rejects_wrong_initial_root_pin_before_metadata_processing() {
        assert_eq!(
            verify_tuf_root_rotation_chain(
                b"not-json".to_vec(),
                vec![0; 32],
                vec![],
                1_700_000_000
            ),
            -1
        );
    }

    #[test]
    fn rejects_oversized_root_and_rotation_chain() {
        assert_eq!(
            verify_tuf_root_rotation_chain(
                vec![1; MAX_ROOT_BYTES + 1],
                vec![0; 32],
                vec![],
                1_700_000_000
            ),
            -1
        );
        assert_eq!(
            verify_tuf_root_rotation_chain(
                b"root".to_vec(),
                vec![0; 32],
                vec![vec![1]; MAX_ROOT_ROTATIONS + 1],
                1_700_000_000
            ),
            -1
        );
    }

    #[test]
    fn rejects_partial_cached_metadata_state() {
        assert!(!verify_tuf_metadata_refresh(
            vec![],
            vec![0; 32],
            vec![],
            Some(vec![1]),
            None,
            None,
            vec![1],
            vec![1],
            vec![1],
            1_700_000_000
        ));
    }

    #[test]
    fn rejects_missing_new_top_level_metadata() {
        assert!(!verify_tuf_metadata_refresh(
            b"root".to_vec(),
            vec![0; 32],
            vec![],
            None,
            None,
            None,
            vec![],
            vec![1],
            vec![1],
            1_700_000_000
        ));
    }

    #[test]
    fn rejects_aggregate_metadata_over_budget() {
        let parts = [vec![0u8; 6], vec![0u8; 5]];
        assert!(!within_byte_budget(parts.iter().map(Vec::as_slice), 10));
        assert!(within_byte_budget(parts.iter().map(Vec::as_slice), 11));
    }

    #[test]
    fn rejects_unsafe_target_paths() {
        assert!(!is_safe_target_path(""));
        assert!(!is_safe_target_path("/absolute/path"));
        assert!(!is_safe_target_path("../escape"));
        assert!(!is_safe_target_path("packages/../../escape"));
        assert!(!is_safe_target_path("packages\\\\escape"));
        assert!(!is_safe_target_path("packages//empty"));
        assert!(is_safe_target_path("releases/mobile/app.tar.zst"));
    }

    #[test]
    fn rejects_mismatched_or_duplicate_delegation_inputs() {
        assert!(!verify_tuf_target_delegation(
            vec![],
            vec![0; 32],
            vec![],
            None,
            None,
            None,
            vec![1],
            vec![1],
            vec![1],
            vec!["release".to_string()],
            vec![],
            "releases/app.tar.zst".to_string(),
            1_700_000_000
        ));
        assert!(!verify_tuf_target_delegation(
            vec![],
            vec![0; 32],
            vec![],
            None,
            None,
            None,
            vec![1],
            vec![1],
            vec![1],
            vec!["release".to_string(), "release".to_string()],
            vec![vec![1], vec![2]],
            "releases/app.tar.zst".to_string(),
            1_700_000_000
        ));
    }

    #[test]
    fn target_search_resolves_a_path_matching_delegated_role() {
        let expiry = Timestamp::from_second(2_000_000_000).unwrap();
        let mut top_level = Targets::new(expiry.clone());
        let mut role = DelegatedRole::new("release", Vec::new(), 1);
        role.paths = Some(vec!["releases/*".to_string()]);
        let mut delegations = Delegations::new();
        delegations.roles.push(role);
        top_level.delegations = Some(delegations);

        let mut delegated = Targets::new(expiry);
        let bytes = b"verified release";
        delegated.targets.insert(
            "releases/app.tar.zst".to_string(),
            TargetFile::from_bytes(bytes, &[HashAlgorithm::Sha256]),
        );

        let mut search = TargetSearch::new("releases/app.tar.zst", 8);
        let top_step = search.next_step().unwrap();
        assert_eq!(top_step.role, "targets");
        assert!(search.visit(&top_step, &top_level).is_none());

        let delegated_step = search.next_step().unwrap();
        assert_eq!(delegated_step.role, "release");
        assert_eq!(delegated_step.delegator, "targets");
        let target = search.visit(&delegated_step, &delegated).unwrap();
        assert!(target.verify(bytes).is_ok());
        assert!(target.verify(b"tampered release").is_err());
        assert!(search.next_step().is_none());
    }

    #[test]
    fn terminating_delegation_prevents_lower_priority_roles() {
        let expiry = Timestamp::from_second(2_000_000_000).unwrap();
        let mut top_level = Targets::new(expiry);
        let mut terminating = DelegatedRole::new("release", Vec::new(), 1);
        terminating.paths = Some(vec!["releases/*".to_string()]);
        terminating.terminating = true;
        let mut fallback = DelegatedRole::new("fallback", Vec::new(), 1);
        fallback.paths = Some(vec!["releases/*".to_string()]);
        let mut delegations = Delegations::new();
        delegations.roles.push(terminating);
        delegations.roles.push(fallback);
        top_level.delegations = Some(delegations);

        let mut search = TargetSearch::new("releases/app.tar.zst", 8);
        let top_step = search.next_step().unwrap();
        assert!(search.visit(&top_step, &top_level).is_none());
        let delegated_step = search.next_step().unwrap();
        assert_eq!(delegated_step.role, "release");
        assert!(search.next_step().is_none());
    }

    #[test]
    fn rejects_invalid_reference_time() {
        assert_eq!(
            verify_tuf_root_rotation_chain(b"root".to_vec(), vec![0; 32], vec![], i64::MAX),
            -1
        );
    }
}
