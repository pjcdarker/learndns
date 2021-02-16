use crate::dns::header::ResponseCode;
use crate::dns::packet::{BytePacketBuffer, Packet};
use crate::dns::question::Question;
use crate::dns::record::QueryType;
use std::error::Error;
use std::net::Ipv4Addr;
use std::net::UdpSocket;

pub struct Server;

impl Server {
    pub fn lookup(
        domain: &str,
        qtype: QueryType,
        server: (Ipv4Addr, u16),
    ) -> Result<Packet, Box<dyn Error>> {
        let mut send_packet_buf = BytePacketBuffer::new();
        let mut send_packet = Packet::new();
        send_packet.header.id = 1000;
        send_packet.header.query_response = false;
        send_packet.header.question_count = 1;
        send_packet.header.recursion_desired = true;
        send_packet
            .questions
            .push(Question::new(domain.into(), qtype));

        send_packet.write(&mut send_packet_buf)?;

        let udp_socket = UdpSocket::bind(("0.0.0.0", 40053))?;
        udp_socket.send_to(&send_packet_buf.buf, server)?;

        let mut rev_packet_buf = BytePacketBuffer::new();
        udp_socket.recv_from(&mut rev_packet_buf.buf)?;

        let rev_packet = Packet::from_buf(&mut rev_packet_buf)?;

        Ok(rev_packet)
    }

    pub fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<Packet, Box<dyn Error>> {
        let mut ns = "198.41.0.4".parse::<Ipv4Addr>()?;

        loop {
            println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

            let ns_copy = ns;
            let server = (ns_copy, 53);
            let res_packet = Server::lookup(qname, qtype, server)?;

            if !res_packet.answers.is_empty()
                && res_packet.header.response_code == ResponseCode::NOERROR
            {
                return Ok(res_packet);
            }

            if res_packet.header.response_code == ResponseCode::NXDOMAIN {
                return Ok(res_packet);
            }

            if let Some(ns_new) = res_packet.resolved_ns(qname) {
                ns = ns_new;
                continue;
            }

            let qname_new = match res_packet.unresolved_ns(qname) {
                Some(v) => v,
                _ => return Ok(res_packet),
            };

            let recursive_pakcet = Server::recursive_lookup(qname_new, QueryType::A)?;
            if let Some(v) = recursive_pakcet.random_answer() {
                ns = v;
                continue;
            }

            return Ok(res_packet);
        }
    }

    pub fn handle_query(socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
        let mut req_packet_buf = BytePacketBuffer::new();
        let (_, src) = socket.recv_from(&mut req_packet_buf.buf)?;
        let mut req_packet = Packet::from_buf(&mut req_packet_buf)?;

        let mut res_packet = Packet::new();
        res_packet.header.id = req_packet.header.id;
        res_packet.header.recursion_desired = true;
        res_packet.header.recursion_available = true;
        res_packet.header.query_response = true;

        if let Some(question) = req_packet.questions.pop() {
            println!("Question: {:?}", question);

            if let Ok(rev_packet) = Server::recursive_lookup(&question.name, question.qtype) {
                res_packet.questions.push(question);
                for rec in rev_packet.answers {
                    println!("Answers: {:#?}", rec);
                    res_packet.answers.push(rec);
                }
                for rec in rev_packet.authorities {
                    println!("authorities: {:#?}", rec);
                    res_packet.authorities.push(rec);
                }
                for rec in rev_packet.additionals {
                    println!("additionals: {:#?}", rec);
                    res_packet.additionals.push(rec);
                }
            }
        } else {
            res_packet.header.response_code = ResponseCode::SERVFAIL;
        }

        let mut res_packet_buf = BytePacketBuffer::new();
        res_packet.write(&mut res_packet_buf)?;

        let len = res_packet_buf.pos();
        let data = res_packet_buf.read_range(0, len)?;
        socket.send_to(data, src)?;

        Ok(())
    }
}
