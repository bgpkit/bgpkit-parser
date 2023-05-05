/*!
Provides parsing of BGP mrt_message.
*/
pub mod attributes;
pub mod messages;
pub use messages::parse_bgp_message;
