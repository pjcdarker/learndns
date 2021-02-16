pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    pub fn read(&mut self) -> Result<u8, String> {
        if self.pos >= 512 {
            return Err("more than 512".to_string());
        }

        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    pub fn read_u16(&mut self) -> Result<u16, String> {
        let b1 = (self.read()? as u16) << 8;
        let b2 = self.read()? as u16;
        let res = b1 | b2;
        Ok(res)
    }

    pub fn read_range(&mut self, start: usize, len: usize) -> Result<&[u8], String> {
        if start + len >= 512 {
            return Err("more than 512".to_string());
        }
        Ok(&self.buf[start..start + len])
    }

    pub fn seek(&mut self, pos: usize) -> Result<(), String> {
        if pos >= 512 {
            return Err("The pos more than 512".to_string());
        }
        self.pos = pos;
        Ok(())
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn get(&mut self, pos: usize) -> Result<u8, String> {
        if pos >= 512 {
            return Err("End of buffer".to_string());
        }
        Ok(self.buf[pos])
    }

    pub fn write(&mut self, b: u8) -> Result<(), String> {
        if self.pos + 1 >= 512 {
            return Err("End of buffer".to_string());
        }

        self.buf[self.pos] = b;
        self.pos += 1;

        Ok(())
    }

    pub fn write_u8(&mut self, b: u8) -> Result<(), String> {
        self.write(b)
    }

    pub fn write_u16(&mut self, b: u16) -> Result<(), String> {
        self.write_u8((b >> 8) as u8)?;
        self.write_u8((b & 0xFF) as u8)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn should_create() {
        let packet_buffer = BytePacketBuffer::new();

        assert_eq!(packet_buffer.pos, 0);
        assert_eq!(packet_buffer.buf.len(), 512);
    }

    #[test]
    fn should_read_byte() {
        let mut packet_buffer = BytePacketBuffer::new();
        let res = packet_buffer.read();

        assert_eq!(packet_buffer.pos, 1);
        assert_eq!(res, Ok(0));
    }

    #[test]
    fn should_read_u16() {
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

        let res = packet_buffer.read_u16();

        assert_eq!(packet_buffer.pos, 2);
        assert_eq!(res, Ok(35419));
    }

    #[test]
    fn should_read_range() {
        let mut packet_buffer = BytePacketBuffer::new();
        let res = packet_buffer.read_range(0, 8);

        assert_eq!(res.unwrap().len(), 8);
    }

    #[test]
    fn should_seek() {
        let mut packet_buffer = BytePacketBuffer::new();
        let _ = packet_buffer.read();

        assert_eq!(packet_buffer.pos, 1);

        let _ = packet_buffer.seek(12);
        assert_eq!(packet_buffer.pos, 12);
    }

    #[test]
    fn should_write() {
        let mut packet_buf = BytePacketBuffer::new();
        let _ = packet_buf.write(0x01);

        assert_eq!(packet_buf.pos(), 1);

        let _ = packet_buf.seek(0);
        assert_eq!(packet_buf.read().unwrap(), 1);
    }
}