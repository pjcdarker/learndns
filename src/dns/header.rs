use crate::dns::packet::BytePacketBuffer;

#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub query_response: bool,
    pub opcode: u8,
    pub authoritative_answer: bool,
    pub truncated_message: bool,
    pub recursion_desired: bool, // 1bit
    pub recursion_available: bool,
    pub reserved: u8,
    pub response_code: ResponseCode,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResponseCode {
    fn value_of(num: usize) -> Self {
        match num {
            1 => ResponseCode::FORMERR,
            2 => ResponseCode::SERVFAIL,
            3 => ResponseCode::NXDOMAIN,
            4 => ResponseCode::NOTIMP,
            5 => ResponseCode::REFUSED,
            _ => ResponseCode::NOERROR,
        }
    }
}

impl Header {
    pub fn new() -> Self {
        Header {
            id: 0,
            query_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: false,
            recursion_available: false,
            reserved: 0,
            response_code: ResponseCode::NOERROR,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    pub fn read(&mut self, packet_buffer: &mut BytePacketBuffer) -> Result<(), String> {
        packet_buffer.seek(0)?;
        self.id = packet_buffer.read_u16()?;
        let b1 = packet_buffer.read()?;
        self.query_response = (b1 & (1 << 7)) > 0;
        self.opcode = (b1 >> 3) & 0xF;
        self.authoritative_answer = (b1 & (1 << 2)) > 0;
        self.truncated_message = (b1 & (1 << 1)) > 0;
        self.recursion_desired = b1 & 1 > 0;

        let b2 = packet_buffer.read()?;
        self.recursion_available = (b2 & (1 << 7)) > 0;
        self.reserved = b2 >> 4 & 0x7;
        self.response_code = ResponseCode::value_of((b2 & 0xF) as usize);
        self.question_count = packet_buffer.read_u16()?;
        self.answer_count = packet_buffer.read_u16()?;
        self.authority_count = packet_buffer.read_u16()?;
        self.additional_count = packet_buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, packet_buf: &mut BytePacketBuffer) -> Result<(), String> {
        packet_buf.write_u16(self.id)?;
        packet_buf.write_u8(
            ((self.query_response as u8) << 7) as u8
                | (self.opcode << 3) as u8
                | ((self.authoritative_answer as u8) << 2) as u8
                | ((self.truncated_message as u8) << 1) as u8
                | self.recursion_desired as u8,
        )?;

        packet_buf.write_u8(
            (self.recursion_available as u8) << 7
                | (self.reserved << 5)
                | (self.response_code as u8),
        )?;

        packet_buf.write_u16(self.question_count)?;
        packet_buf.write_u16(self.answer_count)?;
        packet_buf.write_u16(self.authority_count)?;
        packet_buf.write_u16(self.additional_count)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn should_create() {
        let header = Header::new();

        assert_eq!(header.id, 0);
        assert_eq!(header.opcode, 0);
    }

    #[test]
    fn should_read_from_byte_packet() {
        let mut packet_buffer = create_packet_buffer();
        let mut header = Header::new();
        let result = header.read(&mut packet_buffer);

        assert_eq!(header.id, 35419);
        assert_eq!(header.query_response, true);
        assert_eq!(header.opcode, 0);
        assert_eq!(header.authoritative_answer, true);
        assert_eq!(header.truncated_message, false);
        assert_eq!(header.recursion_desired, true);
        assert_eq!(header.recursion_available, true);
        assert_eq!(header.reserved, 0);
        assert_eq!(header.response_code, ResponseCode::NOERROR);
        assert_eq!(header.question_count, 1);
        assert_eq!(header.answer_count, 1);
        assert_eq!(header.authority_count, 0);
        assert_eq!(header.additional_count, 0);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_write() {
        let mut packet_buf = BytePacketBuffer::new();
        let mut header = Header::new();
        header.id = 35419;
        header.query_response = true;
        header.opcode = 0;
        header.authoritative_answer = true;
        header.truncated_message = false;
        header.recursion_desired = true;
        header.recursion_available = true;
        header.reserved = 0;
        header.response_code = ResponseCode::NOERROR;
        header.question_count = 1;
        header.answer_count = 1;
        header.authority_count = 0;
        header.additional_count = 0;

        let _ = header.write(&mut packet_buf);
        let bytes = [
            0x8a, 0x5b, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let _ = packet_buf.seek(0);
        for e in bytes.iter() {
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
