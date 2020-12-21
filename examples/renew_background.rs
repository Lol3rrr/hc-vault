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

    let client = Client::new(conf, auth).unwrap();

    let client_arc = std::sync::Arc::new(client);

    let cloned = client_arc.clone();
    std::thread::spawn(move || {
        match cloned.renew_background() {
            Err(e) => println!("{}", e),
            Ok(_) => {}
        };
    });

    loop {
        std::thread::sleep(std::time::Duration::from_secs(10))
    }
}
