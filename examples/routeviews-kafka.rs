use std::io::Cursor;
use chrono::format::Item;
use rdkafka::{ClientConfig, ClientContext, Message};
use rdkafka::consumer::{CommitMode, Consumer, ConsumerContext, StreamConsumer};
use bgpkit_parser::{parse_bmp_msg, parse_openbmp_header, parse_openbmp_msg};

// A simple context to customize the consumer behavior and print a log line every time
// offsets are committed
struct LoggingConsumerContext;

impl ClientContext for LoggingConsumerContext {}
impl ConsumerContext for LoggingConsumerContext {}

// Define a new type for convenience
type LoggingConsumer = StreamConsumer<LoggingConsumerContext>;

async fn consume_and_print(brokers: &str, group_id: &str, topics: &[&str]) {
    let consumer: LoggingConsumer = ClientConfig::new()
        .set("group.id", group_id)
        .set("bootstrap.servers", brokers)
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", "6000")
        .set("enable.auto.commit", "true")
        //.set("statistics.interval.ms", "30000")
        //.set("auto.offset.reset", "smallest")
        .create_with_context(LoggingConsumerContext).unwrap();

    consumer
        .subscribe(&topics.to_vec())
        .expect("Can't subscribe to specified topics");

    loop {
        match consumer.recv().await {
            Err(e) => {},
            Ok(m) => {
                let payload = m.payload();
                if let Some(p) = payload {
                    let mut reader = Cursor::new(Vec::from(p));
                    let header = parse_openbmp_header(&mut reader).unwrap();
                    match parse_bmp_msg(&mut reader) {
                        Ok(msg) => {
                            println!("Parsing OK: {:?}", msg.common_header.msg_type);
                        }
                        Err(e) => {
                            println!("{:?}", e);
                            println!("{:?}", header);
                            let hex = hex::encode(p);
                            println!("{}", hex);
                            break
                        }
                    }

                }
                consumer.commit_message(&m, CommitMode::Async).unwrap();
            }
        };
    }
}

#[tokio::main]
pub async fn main(){
    let topic = "^routeviews\\..+\\..+\\.bmp_raw";
    // consume_and_print("stream.routeviews.org", "bgpkit-parser-2", &["routeviews.route-views2.7660.bmp_raw"]).await
    consume_and_print("stream.routeviews.org", "bgpkit-parser-2", &[topic]).await
}