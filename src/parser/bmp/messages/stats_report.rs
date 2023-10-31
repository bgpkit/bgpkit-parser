use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bytes::Bytes;
use num_enum::{FromPrimitive, IntoPrimitive};

#[derive(Debug)]
pub struct StatsReport {
    pub stats_count: u32,
    pub counters: Vec<StatCounter>,
}

/// Statistics count values
#[derive(Debug)]
pub struct StatCounter {
    pub stat_type: StatType,
    pub stat_len: u16,
    pub stat_data: StatsData,
}

/// Stats counter types enum
///
/// Types of BMP statistics are listed here: <https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#statistics-types>
#[derive(Debug, FromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum StatType {
    PrefixesRejectedByInboundPolicy = 0,
    DuplicatePrefixAdvertisements = 1,
    DuplicateWithdrawnPrefixes = 2,
    UpdatesInvalidatedDueToClusterListLoop = 3,
    UpdatesInvalidatedDueToASPathLoop = 4,
    UpdatesInvalidatedDueToOriginatorId = 5,
    UpdatesInvalidatedDueToASConfedLoop = 6,
    RoutesInAdjRibsIn = 7,
    RoutesInLocRib = 8,
    RoutesInPerAfiSafiAdjRibIn = 9,
    RoutesInPerAfiSafiLocRib = 10,
    UpdatesSubjectedToTreatAsWithdraw = 11,
    PrefixesSubjectedToTreatAsWithdraw = 12,
    DuplicateUpdateMessagesReceived = 13,
    RoutesInPrePolicyAdjRibOut = 14,
    RoutesInPostPolicyAdjRibOut = 15,
    RoutesInPerAfiSafiPrePolicyAdjRibOut = 16,
    RoutesInPerAfiSafiPostPolicyAdjRibOut = 17,
    #[num_enum(catch_all)]
    Other(u16) = 65535,
}

#[derive(Debug)]
pub enum StatsData {
    Counter(u32),
    Gauge(u64),
}

pub fn parse_stats_report(data: &mut Bytes) -> Result<StatsReport, ParserBmpError> {
    let stats_count = data.read_u32()?;
    let mut counters = vec![];
    for _ in 0..stats_count {
        let stat_type = StatType::from(data.read_u16()?);
        let stat_len = data.read_u16()?;
        let stat_data = match stat_len {
            4 => StatsData::Counter(data.read_u32()?),
            8 => StatsData::Gauge(data.read_u64()?),
            _ => return Err(ParserBmpError::CorruptedBmpMessage),
        };
        counters.push(StatCounter {
            stat_type,
            stat_len,
            stat_data,
        })
    }

    Ok(StatsReport {
        stats_count,
        counters,
    })
}
