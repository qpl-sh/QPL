// SPDX-License-Identifier: MIT OR Apache-2.0

//! QPL SDK — Async client for quantum-proof signing and STARK proving.
//!
//! # Quick Start
//!
//! ```no_run
//! use qpl_sdk::{QplClient, SdkConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = QplClient::connect(SdkConfig::testnet()).await?;
//!
//! // Threshold ML-DSA signing
//! let sig = client.signing().sign(b"hello", Default::default()).await?;
//!
//! // STARK proving
//! let proof = client.proving().prove(vec![], Default::default()).await?;
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod config;
pub mod errors;
pub mod services;

pub use client::QplClient;
pub use config::SdkConfig;
pub use errors::SdkError;
