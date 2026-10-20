//! Call one WMI method and print its output parameters as JSON.
//!
//! Usage: wmi_method <host> <user> <password> <domain|""> <object-path> <method> [<in-params-json>]
//! The namespace defaults to root/cimv2; set WMI_NAMESPACE to change it.
//! RUST_LOG=fabi_wmi=debug shows the protocol steps.
//!
//! Read-only calls that exercise both input paths:
//!   wmi_method ... __SystemSecurity GetSD
//!   wmi_method ... StdRegProv GetStringValue \
//!     '{"hDefKey":2147483650,"sSubKeyName":"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion","sValueName":"ProductName"}'
use fabi_wmi::{Credentials, WmiClient};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().collect();
    if !(7..=8).contains(&args.len()) {
        eprintln!(
            "usage: {} <host> <user> <password> <domain> <object-path> <method> [<in-params-json>]",
            args[0]
        );
        std::process::exit(2);
    }
    let in_params = match args.get(7) {
        Some(json) => serde_json::from_str(json).unwrap_or_else(|err| {
            eprintln!("in-params are not valid JSON: {err}");
            std::process::exit(2);
        }),
        None => serde_json::Value::Null,
    };
    let host = &args[1];
    let namespace = std::env::var("WMI_NAMESPACE").unwrap_or_else(|_| "root/cimv2".into());
    let creds = Credentials::new(&args[2], &args[3]).with_domain(&args[4]);

    let mut client = match WmiClient::connect(host, &creds, &namespace) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("connect failed: {err} (hresult: {:x?})", err.hresult());
            std::process::exit(1);
        }
    };
    let failed = match client.exec_method(&args[5], &args[6], &in_params) {
        Ok(out) => {
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
            false
        }
        Err(err) => {
            eprintln!("method failed: {err} (hresult: {:x?})", err.hresult());
            true
        }
    };
    drop(client); // releases IWbemServices on the server
    std::process::exit(i32::from(failed));
}
