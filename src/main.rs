mod dns;
use crate::dns::server::Server;
use std::net::UdpSocket;

fn main() {
    let socket = UdpSocket::bind(("0.0.0.0", 4053)).unwrap();
    loop {
        match Server::handle_query(&socket) {
            Ok(_) => {}
            Err(msg) => {
                println!("handle err: {:?}", msg);
            }
        }
    }
}
