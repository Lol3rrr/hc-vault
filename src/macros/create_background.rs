/// This macro can be used to obtain a new Valid Vault session using
/// the given Config and Auth options. Once this new session was obtained
/// it also starts a new thread in the background to periodically renew
/// the newly obtained Vault-Session
///
/// Params:
/// * `conf`: The Configuration to use when obtaining the Vault-Session
/// * `auth`: The Auth instance to use with this Vault-Session
#[macro_export]
macro_rules! create_background {
    ($conf: ident, $auth: ident) => {{
        let config: Config = $conf;
        let auth = $auth;

        let tmp_client = Client::new(config, auth).unwrap();
        let tmp_arc = std::sync::Arc::new(tmp_client);

        let cloned = tmp_arc.clone();
        std::thread::spawn(move || {
            match cloned.renew_background() {
                Err(e) => println!("{}", e),
                Ok(_) => {}
            };
        });

        tmp_arc
    }};
}
