use crate::dns::packet::BytePacketBuffer;
use crate::dns::record::{Domain, QueryType};

#[derive(Debug)]
pub struct Question {
    pub name: String,
    pub qtype: QueryType,
}

impl Question {
    pub fn new(name: String, qtype: QueryType) -> Self {
        Question { name, qtype }
    }

    pub fn read(&mut self, packet_buf: &mut BytePacketBuffer) -> Result<(), String> {
        packet_buf.seek(12)?;
        self.name = Domain::new("".to_string()).read(packet_buf)?;
        self.qtype = QueryType::value_of(packet_buf.read_u16()? & 0xFF);
        packet_buf.read_u16()?;

        Ok(())
    }

    pub fn write(&self, packet_buf: &mut BytePacketBuffer) -> Result<(), String> {
        packet_buf.seek(12)?;
        Domain::new(self.name.clone()).write(packet_buf)?;
        packet_buf.write_u16(self.qtype.num_value())?;
        packet_buf.write_u16(1)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn should_create() {
        let question = Question::new(String::from("github.com"), QueryType::A);

        assert_eq!(question.name, "github.com");
        assert_eq!(question.qtype, QueryType::A);
    }

    #[test]
    fn should_read() {
        let mut packet_buf = create_packet_buffer();
        let mut question = Question::new("".to_string(), QueryType::UNKNOWN(0));
        let _ = question.read(&mut packet_buf);

        assert_eq!(question.name, "google.com");
        assert_eq!(question.qtype, QueryType::A);
    }

    #[test]
    fn should_write() {
        let mut packet_buf = BytePacketBuffer::new();
        let question = Question::new("google.com".to_string(), QueryType::A);

        let _ = question.write(&mut packet_buf);
        let buf = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
            0x00, 0x01,
        ];

        packet_buf.seek(12).unwrap();
        for e in buf.iter() {
            assert_eq!(&packet_buf.read().unwrap(), e);
        }
    }

    fn create_packet_buffer() -> BytePacketBuffer {
        let buffer = [
            0x8a, 0x5b, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, // 00000000
            0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x06, 0x67,
            0x6f, 0x6f, // 00000010
            0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x3c, // 00000020
            0x00, 0x04, 0x5d, 0x2e, 0x08, 0x5a, 0x8a, 0x5b, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, // 00000030
            0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, // 00000040
            0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04,
            0xac, 0xd9, // 00000050
            0xa0, 0x4e, // 00000060
        ];
        let mut packet_buffer = BytePacketBuffer::new();
        for (i, &e) in buffer.iter().enumerate() {
            packet_buffer.buf[i] = e;
        }

        packet_buffer
    }
}
