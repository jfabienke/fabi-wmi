//! Run WQL queries over one login and print each result set as JSON.
//!
//! Usage: wmi_query <host> <user> <password> <domain|""> <wql> [<wql> ...]
//! The namespace defaults to root/cimv2; set WMI_NAMESPACE to change it.
//! RUST_LOG=linux_wmi=debug shows the protocol steps.
use linux_wmi::auth_exports::Credentials;
use linux_wmi::WmiClient;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "usage: {} <host> <user> <password> <domain> <wql> [<wql> ...]",
            args[0]
        );
        std::process::exit(2);
    }
    let host = &args[1];
    let namespace = std::env::var("WMI_NAMESPACE").unwrap_or_else(|_| "root/cimv2".into());
    let creds = Credentials::new(
        args[2].clone(),
        args[3].clone(),
        args[4].clone(),
        String::new(),
    );

    let mut client =
        match WmiClient::connect(host, &creds, &namespace, linux_wmi::wmi_default_timeout()) {
            Ok(client) => client,
            Err(err) => {
                eprintln!("connect failed: {err} (hresult: {:x?})", err.hresult());
                std::process::exit(1);
            }
        };
    let mut failed = false;
    for wql in &args[5..] {
        match client.query(wql) {
            Ok(rows) => println!("{}", serde_json::to_string_pretty(&rows).unwrap()),
            Err(err) => {
                eprintln!("query failed: {err} (hresult: {:x?})", err.hresult());
                failed = true;
            }
        }
    }
    drop(client); // releases IWbemServices on the server
    std::process::exit(i32::from(failed));
}
