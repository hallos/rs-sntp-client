use std::net::UdpSocket;
use std::time::SystemTime;

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

#[derive(Default)]
struct NtpTimestamp {
    seconds: u32,
    fraction: u32,
}

impl NtpTimestamp {
    fn default () -> NtpTimestamp {
        NtpTimestamp {seconds: 0, fraction: 0}
    }
}

#[derive(Default)]
struct SntpPacket {
    bit_field: u8,
    stratum: u8,
    poll: u8,
    precision: u8,
    root_delay: u32,
    root_dispersion: u32,
    reference_id: u32,
    reference_timestamp: NtpTimestamp,
    origin_timestamp: NtpTimestamp,
    receive_timestamp: NtpTimestamp,
    transmit_timestamp: NtpTimestamp,
    key_identifier: u32,
    message_digest: u128,
}

impl SntpPacket {
    fn default () -> SntpPacket {
        SntpPacket {bit_field: 0, stratum: 0, poll: 0, precision: 0, root_delay: 0, root_dispersion: 0, reference_id: 0, reference_timestamp: NtpTimestamp::default(),
            origin_timestamp: NtpTimestamp::default(), receive_timestamp: NtpTimestamp::default(), transmit_timestamp: NtpTimestamp::default(), key_identifier: 0, message_digest: 0}
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

    fn set_transmit_timestamp(&mut self, unix_timestamp_us: u32) {
        self.transmit_timestamp.seconds = unix_timestamp_us / 1000000;
        self.transmit_timestamp.fraction = unix_timestamp_us - self.transmit_timestamp.seconds;
    }

    fn serialize(&self) -> [u8; 48] {
        let mut buffer: [u8; 48] = [0; 48];
        buffer[0] = self.bit_field;
        buffer[1] = self.stratum;
        buffer[2] = self.poll;
        buffer[3] = self.precision;

        let trnsmt_ts_s_bytes = self.transmit_timestamp.seconds.to_be_bytes();
        buffer[40] = trnsmt_ts_s_bytes[0];
        buffer[41] = trnsmt_ts_s_bytes[1];
        buffer[42] = trnsmt_ts_s_bytes[2];
        buffer[43] = trnsmt_ts_s_bytes[3];
        let trnsmt_ts_frac_bytes = self.transmit_timestamp.fraction.to_be_bytes();
        buffer[44] = trnsmt_ts_frac_bytes[0];
        buffer[45] = trnsmt_ts_frac_bytes[1];
        buffer[46] = trnsmt_ts_frac_bytes[2];
        buffer[47] = trnsmt_ts_frac_bytes[3];

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
        ClientRequest {sntp_packet: request_packet}
    }

    fn set_timestamp(&self, unix_timestamp_us: u32) {
        self.sntp_packet.set_transmit_timestamp(unix_timestamp_us);
    }

    fn get_buffer(&self) -> [u8; 48] {
        return self.sntp_packet.serialize();
    }
}




fn main() {
    let request = ClientRequest::default();

    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).expect("set_read_timeout call failed");

    // Take origin/transmit timestamp
    let origin_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_micros(),
        Err(_) => 0,
    };
    request.set_timestamp(origin_timestamp.try_into());

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