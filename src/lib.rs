//! Constitute Gateway library surface.
//!
//! This crate exposes reusable modules for the native gateway runtime:
//! - discovery envelopes and publication helpers
//! - local relay and relay-pool transport helpers
//! - UDP transport and swarm record handling
//! - Nostr bootstrap/fallback event/signature helpers
//! - encrypted keystore utilities

/// Discovery schemas and publication helpers.
pub mod discovery;
/// Gateway hardening observations and network exposure posture.
pub mod hardening;
/// Encrypted key and sensitive state storage.
pub mod keystore;
/// Local websocket relay for browser-side clients.
pub mod local_relay;
/// Report-only cybersec mitigation recommendation consumer posture.
pub mod mitigation;
/// Nostr bootstrap/fallback key/event/signature helpers used across gateway modules.
pub mod nostr;
/// Platform-specific setup and default paths.
pub mod platform;
/// Outbound relay pool client.
pub mod relay;
/// Swarm edge intake, replay protection, propagation planning, and bridge records.
pub mod swarm_edge;
/// WebSocket binding for the generic swarm edge.
pub mod swarm_edge_server;
/// Validated identity/device record store.
pub mod swarm_store;
/// UDP transport and peer signaling primitives.
pub mod transport;
/// Shared utility helpers.
pub mod util;
