//! BMP message parsing.
//!
//! https://datatracker.ietf.org/doc/html/rfc7854

use std::io::{Cursor, Read};
use crate::parser::bmp::error::ParserBmpError;
pub use headers::{BmpCommonHeader, BmpMsgType, BmpPerPeerHeader, parse_bmp_common_header, parse_per_peer_header};
pub use initiation_message::{InitiationMessage, parse_initiation_message};
pub use peer_down_notification::{parse_peer_down_notification, PeerDownNotification};
pub use peer_up_notification::{parse_peer_up_notification, PeerUpNotification};
pub use route_mirroring::{parse_route_mirroring, RouteMirroring};
pub use route_monitoring::{parse_route_monitoring, RouteMonitoring};
pub use stats_report::{parse_stats_report, StatsReport};
pub use termination_message::{parse_termination_message, TerminationMessage};

pub(crate) mod peer_down_notification;
pub(crate) mod headers;
pub(crate) mod initiation_message;
pub(crate) mod termination_message;
pub(crate) mod route_monitoring;
pub(crate) mod route_mirroring;
pub(crate) mod peer_up_notification;
pub(crate) mod stats_report;

#[derive(Debug)]
pub struct BmpMessage {
    pub common_header: BmpCommonHeader,
    pub per_peer_header: Option<BmpPerPeerHeader>,
    pub message_body: MessageBody,
}

#[derive(Debug)]
pub enum MessageBody {
    PeerUpNotification(PeerUpNotification),
    PeerDownNotification(PeerDownNotification),
    InitiationMessage(InitiationMessage),
    TerminationMessage(TerminationMessage),
    RouteMonitoring(RouteMonitoring),
    RouteMirroring(RouteMirroring),
    StatsReport(StatsReport),
}