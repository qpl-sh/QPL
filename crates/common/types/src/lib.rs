// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared types for the QPL (Quantum Proof Layer) platform.
//!
//! This crate provides common type definitions used across all QPL crates,
//! ensuring consistent representations for identifiers, assets, amounts,
//! and PQC cryptographic primitives.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;

// === Identifiers ===

/// Bank identifier within the consortium.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BankId(pub String);

/// Tenant identifier — each bank operates as a sovereign tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

/// Universal asset identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId(pub String);

/// Vault identifier for custody operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VaultId(pub String);

// === Asset Classification ===

/// Classification of assets managed by the platform.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetClass {
    /// Standard sovereign deposit token.
    DepositToken,
    /// Interest-bearing yield token with accrual schedule.
    YieldToken,
    /// Tokenized real-world asset (loan, treasury, bond, etc.).
    RwaToken,
}

// === Financial Primitives ===

/// Precise monetary amount using arbitrary-precision decimals.
/// Wraps `rust_decimal::Decimal` for financial-grade arithmetic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount(pub Decimal);

impl Amount {
    pub fn zero() -> Self {
        Amount(Decimal::ZERO)
    }
    pub fn new(val: i64, scale: u32) -> Self {
        Amount(Decimal::new(val, scale))
    }
    pub fn is_positive(&self) -> bool {
        self.0.is_sign_positive() && self.0 != Decimal::ZERO
    }
    pub fn is_zero(&self) -> bool {
        self.0 == Decimal::ZERO
    }
    pub fn checked_add(&self, other: &Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }
    pub fn checked_sub(&self, other: &Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }
    pub fn checked_mul(&self, other: &Amount) -> Option<Amount> {
        self.0.checked_mul(other.0).map(Amount)
    }
    pub fn inner(&self) -> Decimal {
        self.0
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for BankId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl fmt::Display for VaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// ISO 4217 currency code.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Currency(pub String);

impl Currency {
    pub fn usd() -> Self {
        Currency("USD".into())
    }
    pub fn eur() -> Self {
        Currency("EUR".into())
    }
    pub fn gbp() -> Self {
        Currency("GBP".into())
    }

    /// Returns true if the inner string is a valid ISO 4217 format (3 uppercase ASCII letters).
    pub fn is_valid_iso4217(&self) -> bool {
        self.0.len() == 3 && self.0.bytes().all(|b| b.is_ascii_uppercase())
    }
}

/// Timestamp type using UTC datetime.
pub type Timestamp = DateTime<Utc>;

// === PQC Cryptographic Primitives ===

/// PQC public key (ML-DSA) as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqcPublicKey(pub Vec<u8>);

/// PQC signature (ML-DSA) as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqcSignature(pub Vec<u8>);

/// PQC key pair handle reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyRef(pub String);

// === Sovereign Control ===

/// Represents a sovereign entity (bank) in the consortium.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereignEntity {
    pub bank_id: BankId,
    pub tenant_id: TenantId,
    pub name: String,
    pub jurisdiction: String,
    pub pqc_public_key: PqcPublicKey,
    pub joined_at: Timestamp,
}

/// Status of an entity or asset in the platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityStatus {
    Active,
    Suspended,
    Pending,
    Terminated,
}

// === Common Errors ===

/// Shared error types used across crates.
#[derive(Debug, thiserror::Error)]
pub enum CommonError {
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),

    #[error("amount overflow")]
    AmountOverflow,

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid state transition: {0}")]
    InvalidStateTransition(String),
}
