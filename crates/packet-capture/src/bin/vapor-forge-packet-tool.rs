mod packet_tool;

fn main() {
    if let Err(error) = packet_tool::run() {
        eprintln!("vapor-forge-packet-tool: {error}");
        std::process::exit(1);
    }
}
