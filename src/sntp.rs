use std::net::UdpSocket;
use std::time::SystemTime;
use std::sync::atomic::{AtomicBool, Ordering};
use log::{debug, info, warn, error};


//1.  A client MUST NOT under any conditions use a poll interval less
//than 15 seconds.
//
//2.  A client SHOULD increase the poll interval using exponential
//backoff as performance permits and especially if the server does
//not respond within a reasonable time.
//
//3.  A client SHOULD use local servers whenever available to avoid
//unnecessary traffic on backbone networks.
//
//4.  A client MUST allow the operator to configure the primary and/or
//alternate server names or addresses in addition to or in place of
//a firmware default IP address.
//
//5.  If a firmware default server IP address is provided, it MUST be a
//server operated by the manufacturer or seller of the device or
//another server, but only with the operator's permission.
//
//6.  A client SHOULD use the Domain Name System (DNS) to resolve the
//server IP addresses, so the operator can do effective load
//balancing among a server clique and change IP address binding to
//canonical names.
//
//7.  A client SHOULD re-resolve the server IP address at periodic
//intervals, but not at intervals less than the time-to-live field
//in the DNS response.
//
//8.  A client SHOULD support the NTP access-refusal mechanism so that
//a server kiss-o'-death reply in response to a client request
//causes the client to cease sending requests to that server and to
//switch to an alternate, if available.

// Seconds from NTP timestamp epoch to UNIX epoch
const NTP_TIMESTAMP_UNIX_EPOCH: u32 = 2208988800;
// NTP default UDP port
const NTP_PORT: &str = "123";
// SNTP minimum allowed poll interval
const SNTP_MIN_POLL_INTERVAL: u32 = 15;

#[allow(dead_code)]
pub enum ProtocolMode {
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
}

#[allow(dead_code)]
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

    /// Create a NtpTimestamp from a unix timestamp
    ///
    /// # Arguments
    /// * `unix_timestamp` - std::time::Duration with Unix timestamp to use
    fn from_unix_timestamp(unix_timestamp: std::time::Duration) -> NtpTimestamp {
        // Calculate fraction part of timestamp
        let mut frac: u64 = unix_timestamp.subsec_micros() as u64;
        frac = frac << 32 / 1000000;
        // Construct NtpTimestamp struct
        NtpTimestamp {
            seconds: unix_timestamp.as_secs() as u32 + NTP_TIMESTAMP_UNIX_EPOCH,
            fraction: frac as u32,
        }
    }

    /// Returns timestamp as Unix timestamp with microseconds resolution
    fn get_unix_timestamp(&self) -> std::time::Duration {
        let unix_seconds: u32 = self.seconds - NTP_TIMESTAMP_UNIX_EPOCH;
        let microseconds: u64 = self.fraction as u64 * 1000000;
        std::time::Duration::from_micros(unix_seconds as u64 * 1000000 + (microseconds >> 32))
    }
}

#[derive(Default)]
#[allow(dead_code)]
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

    fn from_bytes(bytes: &[u8; 48]) -> SntpPacket {
        SntpPacket {
            bit_field: bytes[0],
            stratum: bytes[1],
            poll: bytes[2],
            precision: bytes[3],
            root_delay: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            root_dispersion: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            reference_id: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            reference_timestamp: NtpTimestamp {
                seconds: u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
                fraction: u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]])},
            origin_timestamp: NtpTimestamp {
                seconds: u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
                fraction: u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]])},
            receive_timestamp: NtpTimestamp {
                seconds: u32::from_be_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]),
                fraction: u32::from_be_bytes([bytes[36], bytes[37], bytes[38], bytes[39]])},
            transmit_timestamp: NtpTimestamp {
                seconds: u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]),
                fraction: u32::from_be_bytes([bytes[44], bytes[45], bytes[46], bytes[47]])},
            key_identifier: 0,
            message_digest: 0,
        }    
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

    fn set_transmit_timestamp(&mut self, timestamp: NtpTimestamp) {
        self.transmit_timestamp = timestamp;
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

    fn set_timestamp(&mut self, unix_timestamp: std::time::Duration) {
        let timestamp = NtpTimestamp::from_unix_timestamp(unix_timestamp);
        self.sntp_packet.set_transmit_timestamp(timestamp);
    }

    fn get_buffer(&self) -> [u8; 48] {
        return self.sntp_packet.serialize();
    }
}

pub trait SntpResponseHandler {
    fn handle_sntp_response (unix_timestamp: std::time::Duration);
}

#[derive(Default)]
pub struct SntpClient {
    host: String,
    poll_interval: u32,
    thread_handle: Option<std::thread::JoinHandle<()>>,
    run: std::sync::Arc<AtomicBool>,
}

#[allow(dead_code)]
impl SntpClient {
    pub fn new (host: &str) -> SntpClient {
        SntpClient {
            host: host.to_string(),
            run: std::sync::Arc::new(AtomicBool::new(false)),
            thread_handle: None,
            poll_interval: 64
        }
    }

    pub fn set_poll_interval (&mut self, poll_interval: u32) {
        if poll_interval < SNTP_MIN_POLL_INTERVAL {
            warn!("Poll interval less than minimum allowed (15s), setting poll interval to 15s");
            self.poll_interval = 15;
        }
        else {
            self.poll_interval = poll_interval;
        }
    }

    pub fn start (&mut self) {
        self.run.store(true, Ordering::Relaxed);
        let run_thread = self.run.clone();
        let ntp_host = format!("{}:{}", self.host, NTP_PORT);
        let poll_interval: u64 = self.poll_interval.into();

        // Spawn SNTP client thread
        self.thread_handle = match std::thread::Builder::new().name("sntp_client".to_string()).spawn(move || {
            // Create socket
            let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
            socket.set_read_timeout(Some(std::time::Duration::from_secs(3))).expect("set_read_timeout call failed");
            // Perform client task until commanded to stop
            while run_thread.load(Ordering::Relaxed) {
                let mut request = ClientRequest::default();

                // Take origin/transmit timestamp
                let origin_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                    Ok(n) => n,
                    Err(_) => std::time::Duration::ZERO,
                };
                request.set_timestamp(origin_timestamp);

                // Serialize and send request
                let buffer = request.get_buffer();
                match socket.send_to(&buffer, ntp_host.as_str()) {
                    Ok(_bytes) => info!("Sent request to {}", ntp_host),
                    Err(e) => error!("Error sending datagram to NTP host '{}' - {}", ntp_host, e)
                }

                let mut recv_buffer = [0; 48];
                let (_number_of_bytes, _src_addr) = socket.recv_from(&mut recv_buffer).expect("Didn't receive data");

                let response_packet = SntpPacket::from_bytes(&recv_buffer);
                debug!("Reference timestamp: {}.{}, UNIX timestamp: {:?}", response_packet.receive_timestamp.seconds, response_packet.receive_timestamp.fraction, response_packet.receive_timestamp.get_unix_timestamp());

                // Call response handling function with newly received timestamp
                SntpClient::handle_sntp_response(response_packet.receive_timestamp.get_unix_timestamp());

                std::thread::sleep(std::time::Duration::from_secs(poll_interval));
            }
        }) {
            Ok(handle) => Some(handle),
            Err(_e) => None,
        };
    }

    pub fn stop (&mut self) {
        self.run.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod client_test {
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

#[cfg(test)]
mod timestamp_tests {
    use super::*;

    #[test]
    fn test_from_unix_timestamp() {
        let unix_timestamp:u32 = 1648820870;
        let ntp_timestamp = NtpTimestamp::from_unix_timestamp(std::time::Duration::from_secs(unix_timestamp as u64));

        assert_eq!(ntp_timestamp.seconds, NTP_TIMESTAMP_UNIX_EPOCH + unix_timestamp);
    }

    #[test]
    fn test_get_unix_timestamp() {
        let timestamp = 3857980091;
        let expected_timestamp = timestamp - NTP_TIMESTAMP_UNIX_EPOCH;
        let ntp_timestamp = NtpTimestamp { seconds: timestamp, fraction: 0};
        let received_timestamp = ntp_timestamp.get_unix_timestamp();

        assert_eq!(expected_timestamp as u64, received_timestamp.as_secs());
    }
}