use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

fn main() {
    if let Err(error) = run() {
        eprintln!("vapor-forge-pe-scan: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(std::env::args().skip(1))?;
    let mut reports = Vec::new();
    let mut failed = false;

    for path in &args.files {
        match scan_file(path, &args.exports) {
            Ok(report) => reports.push(report),
            Err(error) => {
                failed = true;
                reports.push(PeScanReport::error(path, error));
            }
        }
    }

    match args.format {
        OutputFormat::Text => print_text(&reports),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&reports)
                .map_err(|error| format!("serialize JSON failed: {error}"))?;
            println!("{json}");
        }
    }

    if failed {
        Err("one or more files could not be scanned".to_owned())
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Text,
    Json,
}

struct Args {
    files: Vec<PathBuf>,
    exports: Vec<String>,
    format: OutputFormat,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut files = Vec::new();
        let mut exports = Vec::new();
        let mut format = OutputFormat::Text;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--export" => exports.push(next_value(&mut args, "--export")?),
                "--format" => {
                    format = match next_value(&mut args, "--format")?.as_str() {
                        "text" => OutputFormat::Text,
                        "json" => OutputFormat::Json,
                        other => return Err(format!("unsupported format {other:?}\n{}", usage())),
                    };
                }
                "-h" | "--help" => return Err(usage()),
                other if other.starts_with('-') => {
                    return Err(format!("unknown argument {other:?}\n{}", usage()));
                }
                file => files.push(PathBuf::from(file)),
            }
        }

        if files.is_empty() {
            return Err(usage());
        }

        Ok(Self {
            files,
            exports,
            format,
        })
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value\n{}", usage()))
}

fn usage() -> String {
    concat!(
        "usage: vapor-forge-pe-scan [--format text|json] [--export NAME] FILE...\n",
        "\n",
        "Scans PE files using the same Denuvo section/name and trigger-name logic ",
        "used by vapor-forge-proton-inject."
    )
    .to_owned()
}

#[derive(Serialize)]
struct PeScanReport {
    path: String,
    file_name: Option<String>,
    status: &'static str,
    error: Option<String>,
    pe_kind: Option<&'static str>,
    sections: Vec<String>,
    denuvo_name_match: bool,
    denuvo_section_matches: Vec<String>,
    denuvo_detected: bool,
    trigger_match: bool,
    exports: BTreeMap<String, Option<u32>>,
}

impl PeScanReport {
    fn error(path: &Path, error: String) -> Self {
        Self {
            path: path.display().to_string(),
            file_name: path
                .file_name()
                .and_then(|name| name.to_str())
                .map(ToOwned::to_owned),
            status: "error",
            error: Some(error),
            pe_kind: None,
            sections: Vec::new(),
            denuvo_name_match: vapor_forge_pe::is_denuvo_path(path),
            denuvo_section_matches: Vec::new(),
            denuvo_detected: vapor_forge_pe::is_denuvo_path(path),
            trigger_match: vapor_forge_pe::is_trigger_path(path),
            exports: BTreeMap::new(),
        }
    }
}

fn scan_file(path: &Path, exports: &[String]) -> Result<PeScanReport, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read failed: {error}"))?;
    let pe_kind = vapor_forge_pe::pe_kind(&bytes);
    let sections = vapor_forge_pe::section_names(&bytes);
    let denuvo_section_matches = vapor_forge_pe::denuvo_section_matches(&sections)
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let denuvo_name_match = vapor_forge_pe::is_denuvo_path(path);
    let trigger_match = vapor_forge_pe::is_trigger_path(path);
    let mut export_results = BTreeMap::new();

    for name in exports {
        export_results.insert(name.clone(), vapor_forge_pe::find_export_rva(&bytes, name));
    }

    Ok(PeScanReport {
        path: path.display().to_string(),
        file_name: path
            .file_name()
            .and_then(|name| name.to_str())
            .map(ToOwned::to_owned),
        status: if pe_kind.is_some() { "ok" } else { "not_pe" },
        error: None,
        pe_kind: pe_kind.map(vapor_forge_pe::PeKind::label),
        sections,
        denuvo_detected: denuvo_name_match || !denuvo_section_matches.is_empty(),
        denuvo_name_match,
        denuvo_section_matches,
        trigger_match,
        exports: export_results,
    })
}

fn print_text(reports: &[PeScanReport]) {
    for report in reports {
        println!(
            "{}: status={} pe={} denuvo={} trigger={}",
            report.path,
            report.status,
            report.pe_kind.unwrap_or("-"),
            report.denuvo_detected,
            report.trigger_match
        );
        if let Some(error) = &report.error {
            println!("  error: {error}");
        }
        println!("  denuvo_name_match: {}", report.denuvo_name_match);
        println!(
            "  denuvo_section_matches: {}",
            if report.denuvo_section_matches.is_empty() {
                "-".to_owned()
            } else {
                report.denuvo_section_matches.join(", ")
            }
        );
        println!(
            "  sections: {}",
            if report.sections.is_empty() {
                "-".to_owned()
            } else {
                report.sections.join(", ")
            }
        );
        for (name, rva) in &report.exports {
            match rva {
                Some(rva) => println!("  export {name}: rva=0x{rva:x}"),
                None => println!("  export {name}: missing"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_args() {
        let args = Args::parse([
            "--format".to_owned(),
            "json".to_owned(),
            "--export".to_owned(),
            "LdrLoadDll".to_owned(),
            "ntdll.dll".to_owned(),
        ])
        .unwrap();

        assert_eq!(args.format, OutputFormat::Json);
        assert_eq!(args.exports, vec!["LdrLoadDll"]);
        assert_eq!(args.files, vec![PathBuf::from("ntdll.dll")]);
    }
}
