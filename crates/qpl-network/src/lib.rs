// SPDX-License-Identifier: MIT OR Apache-2.0

//! QPL Network — Decentralized operator network for quantum-proof DeFi services.
//!
//! This crate defines the core types, routing logic, fee calculations, and
//! coordination protocols for the QPL operator network. Operators stake to join,
//! advertise capabilities (signing, proving, settlement, yield, RWA), and earn
//! per-operation fees from protocol integrations.
//!
//! This is a pure library crate with no async runtime dependency — networking
//! and I/O live in the `qpl-node` binary and `qpl-sdk` client.

pub mod coordination;
pub mod discovery;
pub mod errors;
pub mod fees;
pub mod operator;
pub mod protocol;
pub mod routing;
pub mod types;

pub use errors::NetworkError;
pub use types::*;
