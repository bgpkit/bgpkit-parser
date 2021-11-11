use std::io::Cursor;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::bmp::messages::*;
use std::io::Read;
pub use crate::parser::bmp::openbmp::parse_openbmp_header;

pub mod openbmp;
pub mod error;
pub mod messages;

pub fn parse_openbmp_msg(reader: &mut Cursor::<Vec<u8>>) -> Result<BmpMessage, ParserBmpError> {
    let _header = parse_openbmp_header(reader)?;
    parse_bmp_msg(reader)
}

// TODO: change to Take<&mut Cursor<Vec<u8>>
pub fn parse_bmp_msg(reader: &mut Cursor::<Vec<u8>>) -> Result<BmpMessage, ParserBmpError>{

    let total_len = reader.get_ref().len() as u32 - reader.position() as u32;

    let common_header = parse_bmp_common_header(reader)?;

    let mut new_reader = if total_len>common_header.msg_len {
            let diff = total_len - common_header.msg_len;
            let bytes_left = reader.get_ref().len() as u32 - reader.position() as u32;
            reader.take((bytes_left - diff) as u64 )
    } else if total_len == common_header.msg_len {
        reader.take(total_len as u64)
    } else {
        return Err(ParserBmpError::CorruptedBmpMessage)
    };

    // check msg length

    match &common_header.msg_type{
        BmpMsgType::RouteMonitoring => {
            let len_left = new_reader.limit();
            let per_peer_header = parse_per_peer_header(&mut new_reader)?;
            let msg = parse_route_monitoring(&mut new_reader,
                                             &per_peer_header.afi, &per_peer_header.asn_len, len_left)?;
            Ok(
                BmpMessage{
                    common_header,
                    per_peer_header: Some(per_peer_header),
                    message_body: MessageBody::RouteMonitoring(msg)
                }
            )
        }
        BmpMsgType::RouteMirroringMessage => {
            let len_left = new_reader.limit();
            let per_peer_header = parse_per_peer_header(&mut new_reader)?;
            let msg = parse_route_mirroring(&mut new_reader,
                                            &per_peer_header.afi, &per_peer_header.asn_len, len_left)?;
            Ok(
                BmpMessage{
                    common_header,
                    per_peer_header: Some(per_peer_header),
                    message_body: MessageBody::RouteMirroring(msg)
                }
            )
        }
        BmpMsgType::StatisticsReport => {
            let per_peer_header = parse_per_peer_header(&mut new_reader)?;
            let msg = parse_stats_report(&mut new_reader)?;
            Ok(
                BmpMessage{
                    common_header,
                    per_peer_header: Some(per_peer_header),
                    message_body: MessageBody::StatsReport(msg)
                }
            )
        }
        BmpMsgType::PeerDownNotification => {
            let per_peer_header = parse_per_peer_header(&mut new_reader)?;
            let msg = parse_peer_down_notification(&mut new_reader)?;
            Ok(
                BmpMessage{
                    common_header,
                    per_peer_header: Some(per_peer_header),
                    message_body: MessageBody::PeerDownNotification(msg)
                }

            )
        }
        BmpMsgType::PeerUpNotification => {
            let per_peer_header = parse_per_peer_header(&mut new_reader)?;
            let msg = parse_peer_up_notification(&mut new_reader, &per_peer_header.afi)?;
            Ok(
                BmpMessage{
                    common_header,
                    per_peer_header: Some(per_peer_header),
                    message_body: MessageBody::PeerUpNotification(msg)
                }
            )
        }
        BmpMsgType::InitiationMessage => {
            let len_left = new_reader.limit();
            let msg = parse_initiation_message(&mut new_reader, len_left)?;
            Ok(
                BmpMessage{
                    common_header,
                    per_peer_header: None,
                    message_body: MessageBody::InitiationMessage(msg)
                }
            )
        }
        BmpMsgType::TerminationMessage => {
            let len_left = new_reader.limit();
            let msg = parse_termination_message(&mut new_reader, len_left)?;
            Ok(
                BmpMessage{
                    common_header,
                    per_peer_header: None,
                    message_body: MessageBody::TerminationMessage(msg)
                }
            )
        }

    }
}

#[cfg(test)]
#[allow(unused_variables)]
mod tests {
    use std::io::Cursor;
    use crate::parser::bmp::openbmp::parse_openbmp_header;
    use super::*;

    #[test]
    fn test_peer_down_notification() {
        let input = "4f424d500107006400000033800c6184b9c2000c602cbf4f072f3ae149d23486024bc3dadfc4000a69732d63632d626d7031c677060bdd020a9e92be000200de2e3180df3369000000000000000000000000000c726f7574652d76696577733500000001030000003302000000000000000000000000000000000000000000003fda060e00000da30000000061523c36000c0e1c0200000a";
        let decoded = hex::decode(input).unwrap();
        let mut reader = Cursor::new(decoded);
        let _header = parse_openbmp_header(&mut reader).unwrap();
        let msg = parse_bmp_msg(&mut reader).unwrap();
        dbg!(msg);
    }

    #[test]
    fn test_route_monitoring() {
        let input = "4f424d500107005c000000b0800c618881530002f643fef880938d19e9d632c815d1e95a87e1000a69732d61682d626d7031eb4de4e596b282c6a995b067df4abc8cc342f19200000000000000000000000000046c696e780000000103000000b00000c00000000000000000200107f800040000000000001aae000400001aae5474800e02dddf5d00000000ffffffffffffffffffffffffffffffff00800200000069400101005002001602050000192f00001aae0000232a000328eb00032caec008181aae42681aae44581aae464f1aae59d91aae866543000000900e002c00020120200107f800040000000000001aae0004fe8000000000000082711ffffe7f29f100302a0fca8000010a";
        let decoded = hex::decode(input).unwrap();
        let mut reader = Cursor::new(decoded);
        let _header = parse_openbmp_header(&mut reader).unwrap();
        let msg = parse_bmp_msg(&mut reader).unwrap();
        dbg!(msg);
    }

    #[test]
    fn test_statistics_report() {
        let input = "4f424d500107005c000000b0800c618881530002f643fef880938d19e9d632c815d1e95a87e1000a69732d61682d626d7031eb4de4e596b282c6a995b067df4abc8cc342f19200000000000000000000000000046c696e780000000103000000b00000c00000000000000000200107f800040000000000001aae000400001aae5474800e02dddf5d00000000ffffffffffffffffffffffffffffffff00800200000069400101005002001602050000192f00001aae0000232a000328eb00032caec008181aae42681aae44581aae464f1aae59d91aae866543000000900e002c00020120200107f800040000000000001aae0004fe8000000000000082711ffffe7f29f100302a0fca8000010a";
        let decoded = hex::decode(input).unwrap();
        let mut reader = Cursor::new(decoded);
        let _header = parse_openbmp_header(&mut reader).unwrap();
        let msg = parse_bmp_msg(&mut reader).unwrap();
        dbg!(msg);
    }

    #[test]
    fn test_peer_up_notification() {
        let input = "4f424d500107005c000000c3800c618aa447000dcdb7fef880938d19e9d632c815d1e95a87e1000a69732d61682d626d7031eb4de4e596b282c6a995b067df4abc8cc342f19200000000000000000000000000046c696e780000000103000000c30000400000000000000000000000000000000000000000c342e05900001aae5474800e02e0025100000000ffffffffffffffffffffffffffffffff00930200000078400101005002002a020a0000192f00001aae00000d1c000000d1000002d1000069b80000016f0000023f0000013200000163400304c342e059c0083c00d100d100d138c20d1c00030d1c00160d1c00640d1c007b0d1c023f0d1c03870d1c08020d1c2fa01aae42681aae44161aae59d91aae89eb4300000118372e84";
        let decoded = hex::decode(input).unwrap();
        let mut reader = Cursor::new(decoded);
        let _header = parse_openbmp_header(&mut reader).unwrap();
        let msg = parse_bmp_msg(&mut reader).unwrap();
        dbg!(msg);
        todo!()
    }

    #[test]
    fn test_initiation_message() {
        let input = "4f424d500107006400000033800c6184b9c2000c602cbf4f072f3ae149d23486024bc3dadfc4000a69732d63632d626d7031c677060bdd020a9e92be000200de2e3180df3369000000000000000000000000000c726f7574652d76696577733500000001030000003302000000000000000000000000000000000000000000003fda060e00000da30000000061523c36000c0e1c0200000a";
        let decoded = hex::decode(input).unwrap();
        let mut reader = Cursor::new(decoded);
        let _header = parse_openbmp_header(&mut reader).unwrap();
        let msg = parse_bmp_msg(&mut reader).unwrap();
        dbg!(msg);
        todo!()
    }

    #[test]
    fn test_termination_message() {
        let input = "4f424d500107006400000033800c6184b9c2000c602cbf4f072f3ae149d23486024bc3dadfc4000a69732d63632d626d7031c677060bdd020a9e92be000200de2e3180df3369000000000000000000000000000c726f7574652d76696577733500000001030000003302000000000000000000000000000000000000000000003fda060e00000da30000000061523c36000c0e1c0200000a";
        let decoded = hex::decode(input).unwrap();
        let mut reader = Cursor::new(decoded);
        let _header = parse_openbmp_header(&mut reader).unwrap();
        let msg = parse_bmp_msg(&mut reader).unwrap();
        dbg!(msg);
        todo!()
    }

    #[test]
    fn test_route_mirroring_message() {
        let input = "4f424d500107006400000033800c6184b9c2000c602cbf4f072f3ae149d23486024bc3dadfc4000a69732d63632d626d7031c677060bdd020a9e92be000200de2e3180df3369000000000000000000000000000c726f7574652d76696577733500000001030000003302000000000000000000000000000000000000000000003fda060e00000da30000000061523c36000c0e1c0200000a";
        let decoded = hex::decode(input).unwrap();
        let mut reader = Cursor::new(decoded);
        let _header = parse_openbmp_header(&mut reader).unwrap();
        let msg = parse_bmp_msg(&mut reader).unwrap();
        dbg!(msg);
        todo!()
    }

    #[test]
    fn test_corrupted() {
        let input = "4f424d500107005d000001bf800c618aac340005e8f0fef880938d19e9d632c815d1e95a87e1000a69732d61682d626d703161889730db94d69758b5b2aff4c7768b67027513000000000000000000000000000570657274680000000103000001bf0000400000000000000000000000000000000000000000da644c110002255367974005000b5c9a00000000ffffffffffffffffffffffffffffffff018f0200000174400101005002000e02030000192f0002255300001e21400304da644c11c008481e21006e1e21012d1e2107d31e2109631e210968463601f446360a59fde910ccfdec1008fdec1773fdf61e21ffdc2f45ffdc2f48ffdc2f4dffdc4e20ffdc621affdc621bffdc7530c010f000021e2100002af900024636000027150002463600002716000246360000272900024636000027310002463600002733000246360000273500024636000027370002463600002741000246360000277500024636000027a900024636000027af000246360000294f000246360000296300024636000029810002463600002a110002463600002a1b0002463600002cc50002463600002d0b000246360000358f0002463600003593000246360000359500024636000035990002463600003f8000024636000045f4000246360000463200024636000047860002463600004787000246360012023800024636ee6b2805e0ff16000007db000000010001000aff0800000000fc9b40c016de7c28";
        let decoded = hex::decode(input).unwrap();
        let mut reader = Cursor::new(decoded);
        let _header = parse_openbmp_header(&mut reader).unwrap();
        let msg = parse_bmp_msg(&mut reader).unwrap();
        dbg!(msg);
    }
}
