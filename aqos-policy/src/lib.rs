#![no_std]

//! Small, allocation-free policy primitives for the future AQ OS kernel.
//! Cryptographic verification is deliberately injected through a trait so the
//! kernel can bind it to a verified boot implementation or a hardware-backed
//! verifier without making policy code depend on a provider.

pub const STAGE_COUNT: usize = 4;
pub const STAGE_NAMES: [&str; STAGE_COUNT] = ["bootloader", "kernel", "system", "secure_services"];

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Measurement(pub [u8; 32]);

impl Measurement {
    pub const ZERO: Self = Self([0; 32]);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootError {
    WrongStageOrder,
    InvalidVersion,
    Rollback,
    BadSignature,
}

pub trait SignatureVerifier {
    fn verify(&self, stage: usize, version: u64, image: &[u8], signature: &[u8]) -> bool;
}

pub struct Ed25519Verifier {
    vendor_key: VerifyingKey,
}

impl Ed25519Verifier {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, ed25519_dalek::SignatureError> {
        Ok(Self {
            vendor_key: VerifyingKey::from_bytes(bytes)?,
        })
    }
}

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, stage: usize, version: u64, image: &[u8], signature: &[u8]) -> bool {
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        let name = STAGE_NAMES[stage].as_bytes();
        let mut message = [0u8; 64];
        let mut len = 0;
        message[..name.len()].copy_from_slice(name);
        len += name.len();
        message[len] = b'|';
        len += 1;
        message[len..len + 8].copy_from_slice(&version.to_be_bytes());
        len += 8;
        message[len..len + 32].copy_from_slice(&Sha256::digest(image));
        len += 32;
        self.vendor_key.verify(&message[..len], &signature).is_ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootStage<'a> {
    pub name: &'a str,
    pub version: u64,
    pub image: &'a [u8],
    pub signature: &'a [u8],
}

pub struct BootPolicy {
    counters: [u64; STAGE_COUNT],
}

impl BootPolicy {
    pub const fn new() -> Self {
        Self {
            counters: [0; STAGE_COUNT],
        }
    }

    pub fn counters(&self) -> &[u64; STAGE_COUNT] {
        &self.counters
    }

    pub fn verify<V: SignatureVerifier>(
        &mut self,
        stages: &[BootStage<'_>; STAGE_COUNT],
        verifier: &V,
        commit: bool,
    ) -> Result<Measurement, BootError> {
        let mut measurement = [0u8; 32];
        let mut next = [0u64; STAGE_COUNT];
        let mut i = 0;
        while i < STAGE_COUNT {
            let stage = stages[i];
            if stage.name != STAGE_NAMES[i] {
                return Err(BootError::WrongStageOrder);
            }
            if stage.version == 0 {
                return Err(BootError::InvalidVersion);
            }
            if stage.version < self.counters[i] {
                return Err(BootError::Rollback);
            }
            if !verifier.verify(i, stage.version, stage.image, stage.signature) {
                return Err(BootError::BadSignature);
            }
            measurement = extend_measurement(measurement, stage.image);
            next[i] = stage.version;
            i += 1;
        }
        if commit {
            self.counters = next;
        }
        Ok(Measurement(measurement))
    }
}

fn extend_measurement(state: [u8; 32], image: &[u8]) -> [u8; 32] {
    let image_hash = Sha256::digest(image);
    let mut h = Sha256::new();
    h.update(state);
    h.update(image_hash);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Accept;
    impl SignatureVerifier for Accept {
        fn verify(&self, _: usize, _: u64, _: &[u8], _: &[u8]) -> bool {
            true
        }
    }

    fn stages(version: u64) -> [BootStage<'static>; STAGE_COUNT] {
        [
            BootStage {
                name: "bootloader",
                version,
                image: b"bl",
                signature: b"sig",
            },
            BootStage {
                name: "kernel",
                version,
                image: b"kernel",
                signature: b"sig",
            },
            BootStage {
                name: "system",
                version,
                image: b"system",
                signature: b"sig",
            },
            BootStage {
                name: "secure_services",
                version,
                image: b"sec",
                signature: b"sig",
            },
        ]
    }

    #[test]
    fn failed_verification_does_not_commit_counters() {
        let mut policy = BootPolicy::new();
        let _ = policy.verify(&stages(2), &Accept, true).unwrap();
        let result = policy.verify(&stages(1), &Accept, true);
        assert_eq!(result, Err(BootError::Rollback));
        assert_eq!(policy.counters(), &[2, 2, 2, 2]);
    }

    #[test]
    fn measure_does_not_commit() {
        let mut policy = BootPolicy::new();
        let _ = policy.verify(&stages(2), &Accept, false).unwrap();
        assert_eq!(policy.counters(), &[0, 0, 0, 0]);
    }
}
