//! Run one WQL query and print the rows as JSON.
//!
//! Usage: wmi_query <host> <user> <password> <domain|""> <wql> [namespace]
//! RUST_LOG=linux_wmi=debug shows the protocol steps.
use linux_wmi::auth_exports::Credentials;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "usage: {} <host> <user> <password> <domain> <wql> [namespace]",
            args[0]
        );
        std::process::exit(2);
    }
    let (host, wql) = (&args[1], &args[5]);
    let namespace = args.get(6).map_or("root/cimv2", String::as_str);
    let creds = Credentials::new(
        args[2].clone(),
        args[3].clone(),
        args[4].clone(),
        String::new(),
    );

    match linux_wmi::query(host, &creds, namespace, wql) {
        Ok(rows) => println!("{}", serde_json::to_string_pretty(&rows).unwrap()),
        Err(err) => {
            eprintln!("query failed: {err}");
            std::process::exit(1);
        }
    }
}
