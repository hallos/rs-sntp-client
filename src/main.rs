use std::net::UdpSocket;
use std::slice;
use std::mem;

pub enum ProtocolMode {
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
}

pub enum ProtocolVersion {
    SNTPv3,
    SNTPv4,
}

#[repr(packed(2))]
#[derive(Default)]
struct SntpPacket {
    bit_field: u8,
    stratum: u8,
    poll: u8,
    precision: u8,
    root_delay: u32,
    root_dispersion: u32,
    reference_id: u32,
    reference_timestamp: u64,
    origin_timestamp: u64,
    receive_timestamp: u64,
    transmit_timestamp: u64,
    key_identifier: u32,
    message_digest: u128,
}

impl SntpPacket {
    fn default () -> SntpPacket {
        SntpPacket{bit_field: 0, stratum: 0, poll: 0, precision: 0, root_delay: 0, root_dispersion: 0, reference_id: 0, reference_timestamp: 0,
            origin_timestamp: 0, receive_timestamp: 0, transmit_timestamp: 0, key_identifier: 0, message_digest: 0}
    }

    fn set_mode(&mut self, mode: ProtocolMode) {
        self.bit_field = match mode {
            ProtocolMode::Client => self.bit_field | 0x03,
            _ => 0,
        }
    }

    fn set_version(&mut self, version: ProtocolVersion) {
        let protcol_version = match version {
            ProtocolVersion::SNTPv3 => 3,
            ProtocolVersion::SNTPv4 => 4,
        };

        self.bit_field |= protcol_version << 3;
    }

    fn serialize(&self) -> [u8; 48] {
        let mut buffer: [u8; 48] = [0; 48];
        buffer[0] = self.bit_field;
        buffer[1] = self.stratum;
        buffer[2] = self.poll;
        buffer[3] = self.precision;

        return buffer;
    }
}

#[derive(Default)]
struct ClientRequest {
    sntp_packet: SntpPacket,
}

impl ClientRequest {
    fn default () -> ClientRequest {
        let mut request_packet = SntpPacket::default();
        request_packet.set_mode(ProtocolMode::Client);
        request_packet.set_version(ProtocolVersion::SNTPv4);
        ClientRequest{sntp_packet: request_packet}
    }

    fn get_buffer(&self) -> [u8; 48] {
        return self.sntp_packet.serialize();
    }
}




fn main() {
    let request = ClientRequest::default();

    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).expect("set_read_timeout call failed");

    // Serialize and send request
    let buffer = request.get_buffer();
    match socket.send_to(&buffer, "pool.ntp.org:123") {
        Ok(bytes) => println!("Sent request, {} bytes", bytes),
        Err(e) => println!("Error sending datagram: {}", e)
    }

    let mut recv_buffer = [0; 48];
    let (number_of_bytes, src_addr) = socket.recv_from(&mut recv_buffer).expect("Didn't receive data");
    println!("Received {} bytes from {}", number_of_bytes, src_addr);

}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_set_mode_client() {
        let mut packet = SntpPacket::default();
        packet.set_mode(ProtocolMode::Client);

        assert_eq!(packet.bit_field, 0x03);
    }

    #[test]
    fn test_set_version_sntp4() {
        let mut packet = SntpPacket::default();
        packet.set_version(ProtocolVersion::SNTPv4);

        assert_eq!(packet.bit_field, 0b00100000);
    }
}