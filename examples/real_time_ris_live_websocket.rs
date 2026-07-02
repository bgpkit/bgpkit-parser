use bgpkit_parser::{parse_ris_live_message_raw, RisLiveClientMessage, RisSubscribe};
use tungstenite::{connect, Message};

const RIS_LIVE_URL: &str = "ws://ris-live.ripe.net/v1/ws/?client=bgpkit-parser-example";

/// This is an example of subscribing to RIS-Live's streaming data from one host (`rrc21`).
///
/// This example opts into RIS Live's `socketOptions.includeRaw` mode and parses the original
/// BGP wire message. Use `parse_ris_live_message` instead if you want to parse RIS Live's
/// JSON-projected fields without requesting raw bytes.
///
/// For more RIS-Live details, check out their documentation at https://ris-live.ripe.net/manual/
fn main() {
    // connect to RIPE RIS Live websocket server
    let (mut socket, _response) =
        connect(RIS_LIVE_URL).expect("Can't connect to RIS Live websocket server");

    // subscribe to messages from one collector and request hex-encoded raw BGP messages
    let msg = RisSubscribe::new().host("rrc21").include_raw(true);
    socket
        .send(Message::Text(msg.to_json_string().into()))
        .unwrap();

    loop {
        let msg = socket.read().expect("Error reading message").to_string();
        if msg.is_empty() {
            continue;
        }
        match parse_ris_live_message_raw(msg.as_str()) {
            Ok(elems) => {
                for elem in elems {
                    println!("{elem}");
                }
            }
            Err(error) => {
                println!("{error:?}");
            }
        }
    }
}
