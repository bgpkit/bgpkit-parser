use bgp_models::prelude::*;
use bgpkit_parser::BgpkitParser;

/// an very simple example that reads a remote BGP data file and print out the message count.
fn main() {
    let url = "http://archive.routeviews.org/route-views.amsix/bgpdata/2023.02/UPDATES/updates.20230222.0430.bz2";
    let parser = BgpkitParser::new(url).unwrap();
    for record in parser.into_record_iter() {
        match record.message {
            MrtMessage::TableDumpMessage(_) => {}
            MrtMessage::TableDumpV2Message(_) => {}
            MrtMessage::Bgp4Mp(msg) => match msg {
                Bgp4Mp::Bgp4MpStateChange(_) => {}
                Bgp4Mp::Bgp4MpStateChangeAs4(_) => {}
                Bgp4Mp::Bgp4MpMessage(m)
                | Bgp4Mp::Bgp4MpMessageLocal(m)
                | Bgp4Mp::Bgp4MpMessageAs4(m)
                | Bgp4Mp::Bgp4MpMessageAs4Local(m) => match m.bgp_message {
                    BgpMessage::Open(_) => {}
                    BgpMessage::Update(u) => {
                        for attr in &u.attributes {
                            if let AttributeValue::OnlyToCustomer(remote) = attr.value {
                                println!("OTC message found, remote ASN = {remote}");
                            }
                        }
                    }
                    BgpMessage::Notification(_) => {}
                    BgpMessage::KeepAlive(_) => {}
                },
            },
        }
    }
}
