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
    dgst: u128,
}

impl Header {
    fn default () -> Header {
        Header{bit_field: 0, stratum: 0, poll: 0, precision: 0, root_delay: 0, root_dispersion: 0, ref_id: 0, ref_timestamp: 0,
            origin_timestamp: 0, receive_timestamp: 0, transmit_timestamp: 0, dgst: 0}
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

    fn send(&self) {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
        let header_ptr = (&self.header as *const Header) as *const u8;
        let request = unsafe { slice::from_raw_parts(header_ptr, mem::size_of::<Header>()) };
        match socket.send_to(request, "gbg1.ntp.se:123") {
            Ok(bytes) => println!("{}", bytes),
            Err(e) => println!("Error sending datagram: {}", e)
        }
    }
}




fn main() {
    let mut request = Request::default();

    request.set_mode(Mode::NtpMode3);

    request.send();

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