//! [`aws-lc-rs`] crypto backend implementation
//!
//! Implements [`Signer`] and [`VerificationKey`] on various
//! [`aws-lc-rs`] types to permit their direct usage in JWT
//! operations.
//!
//! [`Signer`]: crate::encoding::Signer
//! [`VerificationKey`]: crate::validation::VerificationKey
//! [`aws-lc-rs`]: aws_lc_rs

mod sign;
mod verify;

pub use verify::AwsLcVerificationKey;
