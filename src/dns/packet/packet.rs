use crate::dns::header::Header;
use crate::dns::packet::BytePacketBuffer;
use crate::dns::question::Question;
use crate::dns::record::{QueryType, Record};
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Packet {
    pub fn new() -> Packet {
        Packet {
            header: Header::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn from_buf(buf: &mut BytePacketBuffer) -> Result<Packet, String> {
        let mut packet = Packet::new();
        packet.header.read(buf)?;

        for _ in 0..packet.header.question_count {
            let mut question = Question::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buf)?;
            packet.questions.push(question);
        }

        for _ in 0..packet.header.answer_count {
            let res = Record::read(buf)?;
            packet.answers.push(res);
        }

        for _ in 0..packet.header.authority_count {
            let res = Record::read(buf)?;
            packet.authorities.push(res);
        }

        for _ in 0..packet.header.additional_count {
            let res = Record::read(buf)?;
            packet.additionals.push(res);
        }

        Ok(packet)
    }

    pub fn write(&self, buf: &mut BytePacketBuffer) -> Result<(), String> {
        self.header.write(buf)?;

        for e in self.questions.iter() {
            e.write(buf)?;
        }

        for e in self.answers.iter() {
            e.write(buf)?;
        }

        for e in self.authorities.iter() {
            e.write(buf)?;
        }

        for e in self.additionals.iter() {
            e.write(buf)?;
        }

        Ok(())
    }

    pub fn resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.find_ns(qname)
            .flat_map(|(_, host)| {
                self.additionals.iter().filter_map(move |e| match e {
                    Record::A { domain, ip, .. } if domain == host => Some(ip),
                    _ => None,
                })
            })
            .map(|e| *e)
            .next()
    }

    pub fn unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.find_ns(qname).map(|(_, host)| host).next()
    }

    fn find_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|e| match e {
                Record::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            .filter(move |(domain, ..)| qname.ends_with(*domain))
    }

    pub fn random_answer(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|e| match e {
                Record::A { ip, .. } => Some(ip),
                _ => None,
            })
            .map(|e| *e)
            .next()
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn should_write() {
        let mut packet = Packet::new();
        let mut header = Header::new();
        header.id = 35419;
        header.query_response = true;
        header.opcode = 0;
        header.authoritative_answer = true;
        header.truncated_message = false;
        header.recursion_desired = true;
        header.recursion_available = true;
        header.reserved = 0;
        header.question_count = 1;
        header.answer_count = 1;

        for _ in 0..header.question_count {
            let q = Question::new("google.com".to_string(), QueryType::A);
            packet.questions.push(q);
        }

        for _ in 0..header.answer_count {
            packet.answers.push(Record::A {
                domain: "google.com".to_string(),
                ip: Ipv4Addr::new(93, 46, 8, 90),
                ttl: 60,
            });
        }

        packet.header = header;

        let mut packet_buf = BytePacketBuffer::new();
        let _ = packet.write(&mut packet_buf);

        let buf = [
            0x8a, 0x5b, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, // 00000000
            0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x06, 0x67,
            0x6f, 0x6f, // 00000010
            0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x3c, // 00000020
            0x00, 0x04, 0x5d, 0x2e, 0x08, 0x5a,
        ];

        packet_buf.seek(0).unwrap();

        for b in buf.iter() {
            assert_eq!(&packet_buf.read().unwrap(), b);
        }
    }
}
