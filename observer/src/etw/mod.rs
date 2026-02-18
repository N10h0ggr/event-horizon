pub mod provider;
pub mod controller;
pub mod consumer;
pub mod types;
pub mod errors;
pub mod event_parser;
pub mod utils;
mod manifest_parser;

// Re-export specific items to match `etw::UserTrace`, `etw::Provider`, etc.
pub use controller::UserTrace;
pub use provider::{Provider, EventFilter};
pub use types::{Event, FilterCondition};

// Create a 'filter' module namespace for clean usage: filter::DoesMatch
pub mod filter {
    pub use super::types::FilterCondition::*;
}