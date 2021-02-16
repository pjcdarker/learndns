use crate::dns::packet::BytePacketBuffer;
use crate::dns::record::domain::Domain;
use std::net::Ipv4Addr;

#[derive(Clone, PartialEq, Eq, Debug)]
#[warn(dead_code)]
pub enum Record {
    UNKNOWN {
        domain: String,
        qtype: u16,
        ttl: u32,
        len: u16,
    },
    A {
        domain: String,
        ip: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}

impl QueryType {
    pub fn value_of(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }

    pub fn num_value(&self) -> u16 {
        match *self {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
            QueryType::UNKNOWN(n) => n,
        }
    }
}

impl Record {
    pub fn read(packet_buf: &mut BytePacketBuffer) -> Result<Record, String> {
        let domain = Domain::new("".to_string()).read(packet_buf)?;
        let qtype = packet_buf.read_u16()?;
        let _ = packet_buf.read_u16()?;
        let ttl = packet_buf.read_u16()? as u32 | packet_buf.read_u16()? as u32;
        let len = packet_buf.read_u16()?;

        match QueryType::value_of(qtype) {
            QueryType::A => {
                let ip4_addr = Ipv4Addr::new(
                    packet_buf.read()?,
                    packet_buf.read()?,
                    packet_buf.read()?,
                    packet_buf.read()?,
                );
                return Ok(Record::A {
                    domain: domain,
                    ip: ip4_addr,
                    ttl: ttl,
                });
            }
            QueryType::NS => {
                let cname = Domain::new("".to_string()).read(packet_buf)?;
                Ok(Record::NS {
                    domain: domain,
                    host: cname,
                    ttl: ttl,
                })
            }
            QueryType::CNAME => {
                let cname = Domain::new("".to_string()).read(packet_buf)?;
                Ok(Record::CNAME {
                    domain: domain,
                    host: cname,
                    ttl: ttl,
                })
            }
            _ => {
                packet_buf.seek(packet_buf.pos() + len as usize)?;
                return Ok(Record::UNKNOWN {
                    domain: domain,
                    qtype: qtype,
                    ttl: ttl,
                    len: len,
                });
            }
        }
    }

    pub fn write(&self, packet_buf: &mut BytePacketBuffer) -> Result<(), String> {
        match self {
            Record::A { domain, ip, ttl } => {
                Domain::new(domain.into()).write(packet_buf)?;
                packet_buf.write_u16(QueryType::A.num_value())?;
                packet_buf.write_u16(1)?;
                packet_buf.write_u16((ttl >> 16) as u16)?;
                packet_buf.write_u16((ttl & 0xFF) as u16)?;

                packet_buf.write_u16(4)?;

                let octets = ip.octets();
                packet_buf.write_u8(octets[0])?;
                packet_buf.write_u8(octets[1])?;
                packet_buf.write_u8(octets[2])?;
                packet_buf.write_u8(octets[3])?;
            }
            Record::NS { domain, host, ttl } => {
                Domain::new(domain.into()).write(packet_buf)?;
                packet_buf.write_u16(QueryType::NS.num_value())?;
                packet_buf.write_u16(1)?;
                packet_buf.write_u16((ttl >> 16) as u16)?;
                packet_buf.write_u16((ttl & 0xFF) as u16)?;
                // 2 = first len byte + end len byte(0x00)
                let len = host.len() + 2;
                packet_buf.write_u16(len as u16)?;
                Domain::new(host.into()).write(packet_buf)?;
            }
            Record::CNAME { domain, host, ttl } => {
                Domain::new(domain.into()).write(packet_buf)?;
                packet_buf.write_u16(QueryType::CNAME.num_value())?;
                packet_buf.write_u16(1)?;
                packet_buf.write_u16((ttl >> 16) as u16)?;
                packet_buf.write_u16((ttl & 0xFF) as u16)?;
                // 2 = first len byte + end len byte(0x00)
                let len = host.len() + 2;
                packet_buf.write_u16(len as u16)?;
                Domain::new(host.into()).write(packet_buf)?;
            }

            _ => {
                println!("unknown record: {:?}", self);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn should_read_a_record() {
        let mut packet_buffer = create_packet_buffer();
        let _ = packet_buffer.seek(28);
        let record = Record::read(&mut packet_buffer).unwrap();

        assert_eq!(
            record,
            Record::A {
                domain: "google.com".into(),
                ip: Ipv4Addr::new(93, 46, 8, 90),
                ttl: 60,
            }
        );
    }

    #[test]
    fn should_read_cname_record() {
        let mut packet_buffer = create_cname_packet_buffer();
        let _ = packet_buffer.seek(28);
        let record = Record::read(&mut packet_buffer).unwrap();

        assert_eq!(
            record,
            Record::CNAME {
                domain: "google.com".into(),
                host: "google.com".into(),
                ttl: 60,
            }
        );
    }

    #[test]
    fn should_write_a_record() {
        let mut packet_buf = BytePacketBuffer::new();
        let record = Record::A {
            domain: "google.com".to_string(),
            ip: Ipv4Addr::new(93, 46, 8, 90),
            ttl: 60,
        };

        let _ = record.write(&mut packet_buf);

        let buf = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x5d, 0x2e, 0x08, 0x5a,
        ];

        packet_buf.seek(0).unwrap();
        for b in buf.iter() {
            assert_eq!(&packet_buf.read().unwrap(), b);
        }
    }

    #[test]
    fn should_write_cname_record() {
        let mut packet_buf = BytePacketBuffer::new();
        let record = Record::CNAME {
            domain: "google.com".into(),
            host: "google.com".into(),
            ttl: 60,
        };

        let _ = record.write(&mut packet_buf);

        let buf = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x05,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x0c, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
            0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];

        packet_buf.seek(0).unwrap();
        for b in buf.iter() {
            assert_eq!(&packet_buf.read().unwrap(), b);
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

    fn create_cname_packet_buffer() -> BytePacketBuffer {
        let buffer = [
            0x8a, 0x5b, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, // 00000000
            0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x06, 0x67,
            0x6f, 0x6f, // 00000010
            0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x3c, // 00000020
            0x00, 0x0a, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
            0x00, // cname
            0x5d, 0x2e, 0x08, 0x5a, 0x8a, 0x5b, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x00, // 00000030
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
