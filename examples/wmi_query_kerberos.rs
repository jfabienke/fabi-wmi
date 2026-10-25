//! Run WQL queries over one Kerberos-authenticated login and print each result
//! set as JSON.
//!
//! Usage: wmi_query_kerberos <host-fqdn> <REALM> <wql> [<wql> ...]
//! The ticket comes from the credential cache (`kinit`, `KRB5CCNAME`) and the
//! SPN is host/<host-fqdn>; set WMI_SPN to use another, e.g. to connect to an
//! IP address. The namespace defaults to root/cimv2; set WMI_NAMESPACE to
//! change it.
//! RUST_LOG=fabi_wmi=debug shows the protocol steps.
use fabi_wmi::{Auth, KerberosConfig, WmiClient, DEFAULT_TIMEOUT};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: {} <host-fqdn> <REALM> <wql> [<wql> ...]", args[0]);
        std::process::exit(2);
    }
    let host = &args[1];
    let namespace = std::env::var("WMI_NAMESPACE").unwrap_or_else(|_| "root/cimv2".into());
    let spn = std::env::var("WMI_SPN").unwrap_or_else(|_| format!("host/{host}"));
    let auth = Auth::Kerberos(KerberosConfig::new(args[2].as_str()).with_spn(spn));

    let mut client = match WmiClient::connect_with(host, &auth, &namespace, DEFAULT_TIMEOUT) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("connect failed: {err} (hresult: {:x?})", err.hresult());
            std::process::exit(1);
        }
    };
    let mut failed = false;
    for wql in &args[3..] {
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
