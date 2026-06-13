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
//! let mut signing = client.signing().await?;
//! let sig = signing.sign(b"hello", Default::default()).await?;
//!
//! // STARK proving
//! let mut proving = client.proving().await?;
//! let proof = proving.prove(vec![], Default::default()).await?;
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod config;
pub mod errors;
pub mod generated;
pub mod services;

pub use client::QplClient;
pub use config::SdkConfig;
pub use errors::SdkError;
