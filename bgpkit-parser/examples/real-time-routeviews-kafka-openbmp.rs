extern crate core;

use bgpkit_parser::parser::bmp::messages::MessageBody;
use bgpkit_parser::Elementor;
pub use bgpkit_parser::{parse_bmp_msg, parse_openbmp_header};
use kafka::consumer::{Consumer, FetchOffset, GroupOffsetStorage};
use kafka::error::Error as KafkaError;
use log::{error, info};
use std::io::Cursor;
use std::thread::sleep;
use std::time::Duration;

fn consume_and_print(group: String, topic: String, brokers: Vec<String>) -> Result<(), KafkaError> {
    let mut con = Consumer::from_hosts(brokers)
        .with_topic(topic)
        .with_group(group)
        .with_fetch_max_bytes_per_partition(100_000)
        .with_retry_max_bytes_limit(1_000_000)
        .with_fallback_offset(FetchOffset::Earliest)
        .with_offset_storage(GroupOffsetStorage::Kafka)
        .create()?;

    loop {
        let mss = con.poll()?;
        if mss.is_empty() {
            println!("No messages available right now, wait for 5 seconds.");
            sleep(Duration::from_secs(5));
            continue;
        }

        for ms in mss.iter() {
            for m in ms.messages() {
                let bytes = m.value.to_vec();
                let mut reader = Cursor::new(bytes.as_slice());
                let header = parse_openbmp_header(&mut reader).unwrap();
                let bmp_msg = parse_bmp_msg(&mut reader);
                match bmp_msg {
                    Ok(msg) => {
                        let per_peer_header = msg.per_peer_header.unwrap();
                        match msg.message_body {
                            MessageBody::RouteMonitoring(m) => {
                                for elem in Elementor::bgp_to_elems(
                                    m.bgp_message,
                                    header.timestamp,
                                    &per_peer_header.peer_ip,
                                    &per_peer_header.peer_asn.into(),
                                ) {
                                    info!("{}", elem);
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(_e) => {
                        let hex = hex::encode(bytes);
                        error!("{}", hex);
                        break;
                    }
                }
            }
            let _ = con.consume_messageset(ms);
        }
        con.commit_consumed()?;
    }
}

pub fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let broker = "stream.routeviews.org:9092".to_owned();
    let topic = "routeviews.linx.6830.bmp_raw".to_owned();
    let group = "bgpkit-parser-example".to_owned();

    consume_and_print(group, topic, vec![broker]).unwrap();
}
