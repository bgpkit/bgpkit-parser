use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use std::io::Cursor;

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

pub fn parse_stats_report(reader: &mut Cursor<&[u8]>) -> Result<StatsReport, ParserBmpError> {
    let stats_count = reader.read_32b()?;
    let mut counters = vec![];
    for _ in 0..stats_count {
        let stat_type = reader.read_16b()?;
        let stat_len = reader.read_16b()?;
        let stat_data = match stat_len {
            4 => StatsData::Counter(reader.read_32b()?),
            8 => StatsData::Gauge(reader.read_64b()?),
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
