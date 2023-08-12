/*!
Parse MRT header and content, provides [BgpElem][BgpElem] struct for per-prefix information.

[BgpElem]: crate::BgpElem
*/
pub mod mrt_elem;
pub mod mrt_header;
pub mod mrt_message;
pub mod mrt_record;

pub use mrt_message::bgp4mp::parse_bgp4mp;
pub use mrt_message::table_dump_message::parse_table_dump_message;
pub use mrt_message::table_dump_v2_message::parse_table_dump_v2_message;
pub use mrt_record::parse_mrt_record;
