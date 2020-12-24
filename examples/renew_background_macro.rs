use hc_vault::token;
use hc_vault::Client;
use hc_vault::Config;

fn main() {
    println!("Starting");

    let auth =
        token::Session::new("testToken".to_string(), std::time::Duration::from_secs(10)).unwrap();

    let conf = Config {
        ..Default::default()
    };

    #[allow(unused_variables)]
    let client_arc = hc_vault::create_renewing_session!(conf, auth);

    loop {
        std::thread::sleep(std::time::Duration::from_secs(10))
    }
}
