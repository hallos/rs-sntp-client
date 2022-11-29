mod sntp;


fn main() {
    let mut client = sntp::SntpClient::new("pool.ntp.org:123");

    client.start();

    std::thread::sleep(std::time::Duration::from_secs(30));

    client.stop();
}