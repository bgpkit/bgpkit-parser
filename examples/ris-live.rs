use bgpkit_parser::parser::rislive::parse_ris_live_message;
use serde_json::json;
use tungstenite::{connect, Message};
use url::Url;

const RIS_LIVE_URL: &str = "ws://ris-live.ripe.net/v1/ws/?client=rust-bgpkit-parser";
fn main() {
    // connect to RIPE RIS Live websocket server
    let (mut socket, _response) = connect(Url::parse(RIS_LIVE_URL).unwrap()).expect("Can't connect");

    // subscribe to messages from one collector
    let msg = json!({"type": "ris_subscribe", "data": {"host": "rrc21"}}).to_string();
    socket.write_message(Message::Text(msg)).unwrap();

    loop {
        let msg = socket.read_message().expect("Error reading message");
        if let Ok(elems) = parse_ris_live_message(msg.to_string().as_str()) {
            for elem in elems {
                println!("{}", elem);
            }
        }
    }
}
