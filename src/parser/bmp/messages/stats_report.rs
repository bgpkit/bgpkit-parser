use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bytes::Bytes;

#[derive(Debug)]
pub struct StatsReport {
    pub stats_count: u32,
    pub counters: Vec<StatCounter>,
}

#[derive(Debug)]
pub struct StatCounter {
    pub stat_type: u16,
    pub stat_len: u16,
    pub stat_data: StatsData,
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
        let stat_type = data.read_u16()?;
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
