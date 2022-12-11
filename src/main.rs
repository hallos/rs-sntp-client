use chrono::{TimeZone, Utc};

mod sntp;


impl sntp::SntpResponseHandler for sntp::SntpClient {
    fn handle_sntp_response(unix_timestamp: std::time::Duration) {
        let datetime = Utc.timestamp_opt(unix_timestamp.as_secs() as i64, unix_timestamp.subsec_nanos());
        println!("Current date: {:?}", datetime);
    }
}


fn main() {
    env_logger::init();
    let mut client = sntp::SntpClient::new("pool.ntp.org");
    client.set_poll_interval(15);

    client.start();

    std::thread::sleep(std::time::Duration::from_secs(60));

    client.stop();
}