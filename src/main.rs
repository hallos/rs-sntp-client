use std::net::UdpSocket;
use std::slice;
use std::mem;

#[repr(packed(2))]
#[derive(Default)]
struct Header {
    bit_field: u8,
    stratum: u8,
    poll: u8,
    precision: u8,
    root_delay: u32,
    root_dispersion: u32,
    ref_id: u32,
    ref_timestamp: u64,
    origin_timestamp: u64,
    receive_timestamp: u64,
    transmit_timestamp: u64,
}

impl Header {
    fn default () -> Header {
        Header{bit_field: 0, stratum: 0, poll: 0, precision: 0, root_delay: 0, root_dispersion: 0, ref_id: 0, ref_timestamp: 0,
            origin_timestamp: 0, receive_timestamp: 0, transmit_timestamp: 0}
    }
}

pub enum Mode {
    NtpMode1,
    NtpMode2,
    NtpMode3,
    NtpMode4,
}

#[derive(Default)]
struct Request {
    header: Header,
}

impl Request {
    fn default () -> Request { 
        Request{header: Header::default()}
    }

    fn set_mode(&mut self, mode: Mode) {
        self.header.bit_field = match mode {
            Mode::NtpMode3 => self.header.bit_field | 0x03,
            _ => 0,
        }
    }

    fn set_version(&mut self, version: u8) {
        if version <= 4 {
            self.header.bit_field |= version << 3;
        }
    }

    fn serialize(&self) -> [u8; 48] {
        let mut buffer: [u8; 48] = [0; 48];
        buffer[0] = self.header.bit_field;
        buffer[1] = self.header.stratum;
        buffer[2] = self.header.poll;
        buffer[3] = self.header.precision;

        return buffer;
    }
}




fn main() {
    let mut request = Request::default();

    request.set_mode(Mode::NtpMode3);
    request.set_version(4);

    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).expect("set_read_timeout call failed");

    // Serialize and send request
    let buffer = request.serialize();
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
    fn test_set_ntpmode3() {
        let mut request = Request::default();
        request.set_mode(Mode::NtpMode3);

        assert_eq!(request.header.bit_field, 0x03);
    }
}