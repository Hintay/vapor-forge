use std::path::PathBuf;

use serde_json::json;
use vapor_forge_patterns::vtable_scan::{scan_file, DEFAULT_INTERFACES};

fn main() {
    if let Err(error) = run() {
        eprintln!("vapor-forge-vtable-scan: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(std::env::args().skip(1))?;
    let interfaces = args.interfaces();
    let mut reports = Vec::new();

    for path in &args.paths {
        let report = scan_file(path, interfaces.as_deref())?;
        if report
            .interfaces
            .iter()
            .any(|interface| interface.name == "IClientConfigStore")
        {
            vapor_forge_patterns::vtable_scan::validate_config_store_uint64_abi(path, &report)
                .map_err(|error| format!("{}: {error}", path.display()))?;
        }
        reports.push(report);
    }

    if args.json {
        print_json(&reports)?;
    } else {
        print_text(&reports);
    }

    Ok(())
}

#[derive(Debug)]
struct Args {
    json: bool,
    all: bool,
    interfaces: Vec<String>,
    paths: Vec<PathBuf>,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut json = false;
        let mut all = false;
        let mut interfaces = Vec::new();
        let mut paths = Vec::new();
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--json" => json = true,
                "--all" => all = true,
                "--interface" | "-i" => {
                    interfaces.push(next_value(&mut args, "--interface")?);
                }
                "-h" | "--help" => return Err(usage()),
                other if other.starts_with('-') => {
                    return Err(format!("unknown argument {other:?}\n{}", usage()));
                }
                path => paths.push(PathBuf::from(path)),
            }
        }

        if all && !interfaces.is_empty() {
            return Err(format!(
                "--all and --interface cannot be used together\n{}",
                usage()
            ));
        }
        if paths.is_empty() {
            return Err(usage());
        }

        Ok(Self {
            json,
            all,
            interfaces,
            paths,
        })
    }

    fn interfaces(&self) -> Option<Vec<String>> {
        if self.all {
            None
        } else if self.interfaces.is_empty() {
            Some(DEFAULT_INTERFACES.iter().map(|s| (*s).to_owned()).collect())
        } else {
            Some(self.interfaces.clone())
        }
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value\n{}", usage()))
}

fn usage() -> String {
    "usage: vapor-forge-vtable-scan [--json] [--all | -i IFACE ...] STEAMCLIENT_SO...".to_owned()
}

fn print_text(reports: &[vapor_forge_patterns::vtable_scan::VtableScanReport]) {
    for report in reports {
        println!(
            "{}: {} candidates={} interfaces={}",
            report.path,
            report.elf_class.label(),
            report.candidate_count,
            report.interfaces.len()
        );
        for iface in &report.interfaces {
            let named = iface
                .methods
                .iter()
                .filter(|method| !method.name.is_empty())
                .count();
            println!(
                "  {} vtable=0x{:x} candidates={} slots={} named={}",
                iface.name,
                iface.vtable_va,
                iface.candidate_count,
                iface.methods.len(),
                named
            );
            for method in iface.methods.iter().filter(|m| !m.name.is_empty()) {
                if method.func_hash != 0 {
                    println!(
                        "    {:3} {:36} func=0x{:x} hash=0x{:08x}",
                        method.slot, method.name, method.func_va, method.func_hash
                    );
                } else {
                    println!(
                        "    {:3} {:36} func=0x{:x}",
                        method.slot, method.name, method.func_va
                    );
                }
            }
        }
        if let Some(summary) = config_store_summary(report) {
            println!(
                "  IClientConfigStore uint64 ABI get_slot={} set_slot={} get_hash=0x{:08x} set_hash=0x{:08x}",
                summary.get_slot, summary.set_slot, summary.get_hash, summary.set_hash
            );
        }
    }
}

fn print_json(
    reports: &[vapor_forge_patterns::vtable_scan::VtableScanReport],
) -> Result<(), String> {
    let value = json!({
        "modules": reports.iter().map(|report| {
            let config_store = config_store_summary(report);
            json!({
                "path": report.path,
                "elf_class": report.elf_class.label(),
                "candidate_count": report.candidate_count,
                "config_store_uint64_abi": config_store.map(|summary| json!({
                    "get_slot": summary.get_slot,
                    "set_slot": summary.set_slot,
                    "get_hash": format!("0x{:08x}", summary.get_hash),
                    "set_hash": format!("0x{:08x}", summary.set_hash),
                })),
                "interfaces": report.interfaces.iter().map(|iface| {
                    json!({
                        "name": iface.name,
                        "vtable_va": format!("0x{:x}", iface.vtable_va),
                        "candidate_count": iface.candidate_count,
                        "methods": iface.methods.iter().map(|method| {
                            json!({
                                "slot": method.slot,
                                "name": method.name,
                                "func_va": format!("0x{:x}", method.func_va),
                                "func_hash": if method.func_hash == 0 {
                                    serde_json::Value::Null
                                } else {
                                    json!(format!("0x{:08x}", method.func_hash))
                                },
                            })
                        }).collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?;
    println!("{text}");
    Ok(())
}

fn config_store_summary(
    report: &vapor_forge_patterns::vtable_scan::VtableScanReport,
) -> Option<vapor_forge_patterns::vtable_scan::ConfigStoreUint64AbiSummary> {
    report
        .interfaces
        .iter()
        .any(|interface| interface.name == "IClientConfigStore")
        .then(|| {
            vapor_forge_patterns::vtable_scan::validate_config_store_uint64_abi(
                &PathBuf::from(&report.path),
                report,
            )
            .expect("config-store semantics were validated before reporting")
        })
}
