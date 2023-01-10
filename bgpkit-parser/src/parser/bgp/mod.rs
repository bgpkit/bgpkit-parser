/*!
Provides parsing of BGP messages.
*/
pub mod messages;
pub mod attributes;

pub use messages::parse_bgp_message;