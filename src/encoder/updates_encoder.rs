use crate::bmp::messages::BmpMessage;

use bytes::Bytes;

#[derive(Default)]
pub struct MrtUpdatesEncoder {}

impl MrtUpdatesEncoder {
    pub fn encode_bmp_message(&self, message: &BmpMessage) -> Result<Bytes, String> {
        let mrt_record = match crate::models::MrtRecord::try_from(message) {
            Ok(r) => r,
            Err(msg) => {
                return Err(msg);
            }
        };

        let bytes = mrt_record.encode();

        Ok(bytes)
    }
}
