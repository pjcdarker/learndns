use crate::dns::packet::BytePacketBuffer;

pub struct Domain {
    name: String,
}

impl Domain {
    pub fn new(name: String) -> Domain {
        Domain { name }
    }

    pub fn read(&self, packet_buf: &mut BytePacketBuffer) -> Result<String, String> {
        let mut result = String::new();
        let mut jumped = false;
        let mut pos = packet_buf.pos();
        loop {
            let len = packet_buf.get(pos)?;
            if len & 0xc0 == 0xc0 {
                if !jumped {
                    packet_buf.seek(pos + 2)?;
                    jumped = true;
                }

                let b1 = (len as u16) << 8;
                let b2 = packet_buf.get(pos + 1)? as u16;
                pos = ((b1 | b2) ^ 0xc000) as usize;

                continue;
            }

            pos += 1;
            if len == 0 {
                break;
            }

            if result.len() > 0 {
                result.push_str(".");
            }

            result.push_str(&String::from_utf8_lossy(
                packet_buf.read_range(pos, len as usize)?,
            ));
            pos += len as usize;
        }

        if !jumped {
            packet_buf.seek(pos)?;
        }

        Ok(result)
    }

    pub fn write(&self, packet_buf: &mut BytePacketBuffer) -> Result<(), String> {
        self.name.to_string().split(".").for_each(|e| {
            packet_buf.write_u8(e.len() as u8).unwrap();
            e.bytes().for_each(|b| packet_buf.write_u8(b).unwrap());
        });

        packet_buf.write_u8(0)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn should_read_question() {
        let mut packet_buffer = create_packet_buffer();
        packet_buffer.seek(12).unwrap();

        let domain = Domain::new("".to_string())
            .read(&mut packet_buffer)
            .unwrap();

        assert_eq!(domain, "google.com");
    }

    #[test]
    fn should_read_answer() {
        let mut packet_buffer = create_packet_buffer();
        packet_buffer.seek(28).unwrap();

        let domain = Domain::new("".to_string())
            .read(&mut packet_buffer)
            .unwrap();

        assert_eq!(domain, "google.com");
    }

    #[test]
    fn should_write() {
        let mut packet_buf = BytePacketBuffer::new();
        let domain = Domain::new("google.com".to_string());
        let _ = domain.write(&mut packet_buf);

        let buf = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];

        packet_buf.seek(0).unwrap();
        for e in buf.iter() {
            assert_eq!(&packet_buf.read().unwrap(), e);
        }
    }

    fn create_packet_buffer() -> BytePacketBuffer {
        let buffer = [
            0x86, 0x2a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xd8, 0x3a,
            0xd3, 0x8e,
        ];

        let mut packet_buffer = BytePacketBuffer::new();
        for (i, &e) in buffer.iter().enumerate() {
            packet_buffer.buf[i] = e;
        }

        packet_buffer
    }
}
