//! Shared TUF trust-root verification core for the iOS and Android companions.
//!
//! Prototype only. The initial root must be pinned out-of-band; this function
//! checks its exact SHA-256 before validating its self-signature threshold and
//! every sequential root rotation.

uniffi::setup_scaffolding!();

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tuffet::jiff::Timestamp;
use tuffet::pouf::Json;
use tuffet::trusted::TrustedMetadata;

const MAX_ROOT_BYTES: usize = 5 * 1024 * 1024;
const MAX_ROOT_ROTATIONS: usize = 64;

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rejects_invalid_reference_time() {
        assert_eq!(
            verify_tuf_root_rotation_chain(
                b"root".to_vec(),
                vec![0; 32],
                vec![],
                i64::MAX
            ),
            -1
        );
    }
}
