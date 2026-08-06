use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use keyvalues_parser::Obj;
use serde::Serialize;
use sha2::{Digest, Sha256};
use vapor_forge_patterns::scan::{scan_module, ModuleScanReport, PatternScanEntry};
use zip::ZipArchive;

const CDN_BASE: &str = "https://client-update.akamai.steamstatic.com";
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PACKAGE_BYTES: u64 = 256 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("vapor-forge-steam-cdn-fetch: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(std::env::args().skip(1))?;
    std::fs::create_dir_all(&args.out_dir)
        .map_err(|error| format!("create {} failed: {error}", args.out_dir.display()))?;

    let manifest_url = args.channel.manifest_url();
    args.text_print(format_args!("manifest_url={manifest_url}"));
    let manifest_text = http_get_string(manifest_url, MAX_MANIFEST_BYTES)?;
    let manifest = Manifest::parse(&manifest_text)?;
    args.text_print(format_args!("channel={}", args.channel.name()));
    args.text_print(format_args!("version={}", manifest.version));

    if let Some(expected) = args.version.as_deref() {
        if manifest.version != expected {
            return Err(format!(
                "manifest version mismatch: expected {expected}, got {}",
                manifest.version
            ));
        }
    }

    let mut packages = Vec::new();
    for package in args.package_requests() {
        packages.push(fetch_package(&args, &manifest, package)?);
    }

    let (scans, scan_failed) = if args.scan {
        scan_extracted_libraries(&args, &packages)
    } else {
        (Vec::new(), false)
    };

    if args.format == OutputFormat::Json {
        let pattern_failures = collect_pattern_failures(&scans);
        let output = JsonOutput {
            manifest_url: manifest_url.to_owned(),
            channel: args.channel.name(),
            version: manifest.version,
            out_dir: args.out_dir.display().to_string(),
            packages,
            scan_enabled: args.scan,
            scan_unsupported: args.scan_unsupported,
            scans,
            pattern_failures,
        };
        let json = serde_json::to_string_pretty(&output)
            .map_err(|error| format!("serialize JSON failed: {error}"))?;
        println!("{json}");
    }

    if scan_failed {
        Err("one or more patterns failed".to_owned())
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Channel {
    Public,
    PublicBeta,
}

impl Channel {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "public" | "stable" => Ok(Self::Public),
            "publicbeta" | "beta" => Ok(Self::PublicBeta),
            other => Err(format!("unsupported channel {other:?}")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::PublicBeta => "publicbeta",
        }
    }

    fn manifest_url(self) -> &'static str {
        match self {
            Self::Public => "https://client-update.akamai.steamstatic.com/steam_client_ubuntu12",
            Self::PublicBeta => {
                "https://client-update.akamai.steamstatic.com/steam_client_publicbeta_ubuntu12"
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Arch {
    X86,
    X64,
    Both,
}

impl Arch {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "x86" | "i386" | "i686" | "32" | "32bit" => Ok(Self::X86),
            "x64" | "x86_64" | "amd64" | "64" | "64bit" => Ok(Self::X64),
            "both" | "all" => Ok(Self::Both),
            other => Err(format!("unsupported arch {other:?}")),
        }
    }
}

#[derive(Clone, Copy)]
enum PackageKind {
    Ubuntu12,
    SteamRt,
}

impl PackageKind {
    fn manifest_key(self) -> &'static str {
        match self {
            Self::Ubuntu12 => "bins_ubuntu12",
            Self::SteamRt => "bins_steamrt_ubuntu12",
        }
    }

    fn output_name(self) -> &'static str {
        match self {
            Self::Ubuntu12 => "ubuntu12",
            Self::SteamRt => "steamrt",
        }
    }
}

#[derive(Clone, Copy)]
struct PackageRequest {
    kind: PackageKind,
    library_roots: &'static [&'static str],
}

const ROOTS_UBUNTU12_32: &[&str] = &["ubuntu12_32"];
const ROOTS_STEAMRT64: &[&str] = &["steamrt64"];
const ROOTS_STEAMRT_BOTH: &[&str] = &["steamrt32", "steamrt64"];

struct Args {
    channel: Channel,
    arch: Option<Arch>,
    version: Option<String>,
    out_dir: PathBuf,
    keep_zip: bool,
    format: OutputFormat,
    scan: bool,
    scan_unsupported: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OutputFormat {
    Text,
    Json,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut channel = Channel::Public;
        let mut arch = None;
        let mut version = None;
        let mut out_dir = std::env::temp_dir().join("vapor-steam-cdn");
        let mut keep_zip = true;
        let mut format = OutputFormat::Text;
        let mut scan = false;
        let mut scan_unsupported = false;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--channel" => channel = Channel::parse(&next_value(&mut args, "--channel")?)?,
                "--arch" => arch = Some(Arch::parse(&next_value(&mut args, "--arch")?)?),
                "--version" => version = Some(next_value(&mut args, "--version")?),
                "--out" => out_dir = PathBuf::from(next_value(&mut args, "--out")?),
                "--no-keep-zip" => keep_zip = false,
                "--scan" => scan = true,
                "--scan-unsupported" => {
                    scan = true;
                    scan_unsupported = true;
                }
                "--format" => {
                    let value = next_value(&mut args, "--format")?;
                    format = match value.as_str() {
                        "text" => OutputFormat::Text,
                        "json" => OutputFormat::Json,
                        other => return Err(format!("unsupported format {other:?}\n{}", usage())),
                    };
                }
                "-h" | "--help" => return Err(usage()),
                other => return Err(format!("unknown argument {other:?}\n{}", usage())),
            }
        }

        Ok(Self {
            channel,
            arch,
            version,
            out_dir,
            keep_zip,
            format,
            scan,
            scan_unsupported,
        })
    }

    fn package_requests(&self) -> Vec<PackageRequest> {
        let request = |kind, library_roots| PackageRequest {
            kind,
            library_roots,
        };

        match self.arch {
            None => match self.channel {
                Channel::Public => vec![request(PackageKind::Ubuntu12, ROOTS_UBUNTU12_32)],
                Channel::PublicBeta => vec![request(PackageKind::SteamRt, ROOTS_STEAMRT_BOTH)],
            },
            Some(Arch::X86) => vec![request(PackageKind::Ubuntu12, ROOTS_UBUNTU12_32)],
            Some(Arch::X64) => vec![request(PackageKind::SteamRt, ROOTS_STEAMRT64)],
            Some(Arch::Both) => vec![
                request(PackageKind::Ubuntu12, ROOTS_UBUNTU12_32),
                request(PackageKind::SteamRt, ROOTS_STEAMRT64),
            ],
        }
    }

    fn text_print(&self, args: std::fmt::Arguments<'_>) {
        if self.format == OutputFormat::Text {
            println!("{args}");
        }
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value\n{}", usage()))
}

fn usage() -> String {
    concat!(
        "usage: vapor-forge-steam-cdn-fetch ",
        "[--channel public|publicbeta] [--arch x86|x64|both] ",
        "[--version MANIFEST_VERSION] [--out DIR] [--no-keep-zip] ",
        "[--scan] [--scan-unsupported] [--format text|json]\n",
        "\n",
        "Defaults: --channel public uses x86; --channel publicbeta uses steamrt32+steamrt64; ",
        "--out $TMPDIR/vapor-steam-cdn"
    )
    .to_owned()
}

struct Manifest {
    version: String,
    packages: HashMap<String, PackageInfo>,
}

struct PackageInfo {
    file: String,
    size: u64,
    sha2: String,
}

#[derive(Serialize)]
struct JsonOutput {
    manifest_url: String,
    channel: &'static str,
    version: String,
    out_dir: String,
    packages: Vec<JsonPackage>,
    scan_enabled: bool,
    scan_unsupported: bool,
    scans: Vec<JsonPatternScan>,
    pattern_failures: Vec<JsonPatternFailure>,
}

#[derive(Serialize)]
struct JsonPackage {
    package: &'static str,
    url: String,
    size: u64,
    sha2: String,
    zip_path: String,
    reused_zip: bool,
    verified_sha2: String,
    extracted: Vec<JsonExtractedFile>,
}

#[derive(Serialize)]
struct JsonExtractedFile {
    path: String,
    size: u64,
    modified: String,
}

#[derive(Serialize)]
struct JsonPatternScan {
    module: String,
    path: String,
    arch_bits: u8,
    status: &'static str,
    expected_miss: bool,
    reason: Option<String>,
    text_file_off: Option<u64>,
    text_vaddr: Option<u64>,
    text_size: Option<usize>,
    ok_count: usize,
    miss_count: usize,
    failures: Vec<JsonPatternFailure>,
    entries: Vec<JsonPatternEntry>,
}

#[derive(Clone, Serialize)]
struct JsonPatternFailure {
    module: String,
    path: String,
    arch_bits: u8,
    pattern: String,
    status: String,
    hits: usize,
    error: Option<String>,
}

#[derive(Serialize)]
struct JsonPatternEntry {
    pattern: String,
    status: String,
    hits: usize,
    target_offset: Option<usize>,
    error: Option<String>,
}

impl Manifest {
    fn parse(text: &str) -> Result<Self, String> {
        let root_text = first_top_level_vdf(text)?;
        let parsed = keyvalues_parser::parse(root_text)
            .map_err(|error| format!("parse manifest failed: {error}"))?;
        let root = parsed
            .value
            .get_obj()
            .ok_or_else(|| "manifest root is not an object".to_owned())?;
        let version = obj_str(root, "version")
            .ok_or_else(|| "manifest missing version".to_owned())?
            .to_owned();
        let mut packages = HashMap::<String, PackageInfo>::new();

        for (section, values) in root.iter() {
            for value in values {
                let Some(fields) = value.get_obj() else {
                    continue;
                };
                if let Some(package) = PackageInfo::from_obj(section, fields)? {
                    packages.insert(section.to_string(), package);
                    break;
                }
            }
        }

        Ok(Self { version, packages })
    }
}

fn first_top_level_vdf(text: &str) -> Result<&str, String> {
    let bytes = text.as_bytes();
    let mut in_string = false;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut saw_object = false;
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];

        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' => {
                depth += 1;
                saw_object = true;
            }
            b'}' => {
                if depth == 0 {
                    return Err("manifest has unmatched closing brace".to_owned());
                }
                depth -= 1;
                if depth == 0 && saw_object {
                    return Ok(&text[..=index]);
                }
            }
            _ => {}
        }

        index += 1;
    }

    if saw_object {
        Err("manifest root object is not closed".to_owned())
    } else {
        Err("manifest missing root object".to_owned())
    }
}

impl PackageInfo {
    fn from_obj(section: &str, fields: &Obj<'_>) -> Result<Option<Self>, String> {
        let Some(file) = obj_str(fields, "file") else {
            return Ok(None);
        };
        let Some(sha2) = obj_str(fields, "sha2") else {
            return Ok(None);
        };
        let size = obj_str(fields, "size")
            .ok_or_else(|| format!("package {section} missing size"))?
            .parse::<u64>()
            .map_err(|error| format!("package {section} has invalid size: {error}"))?;
        Ok(Some(Self {
            file: file.to_owned(),
            size,
            sha2: sha2.to_owned(),
        }))
    }
}

fn obj_str<'a>(obj: &'a Obj<'a>, key: &str) -> Option<&'a str> {
    obj.get(key)?.first()?.get_str()
}

fn fetch_package(
    args: &Args,
    manifest: &Manifest,
    request: PackageRequest,
) -> Result<JsonPackage, String> {
    let kind = request.kind;
    let key = kind.manifest_key();
    let package = manifest
        .packages
        .get(key)
        .ok_or_else(|| format!("manifest missing package {key:?}"))?;
    let url = format!("{CDN_BASE}/{}", package.file);
    let zip_name = format!("{}_{}.zip", kind.manifest_key(), args.channel.name());
    let zip_path = args.out_dir.join(zip_name);
    args.text_print(format_args!("package={key}"));
    args.text_print(format_args!("package_url={url}"));
    args.text_print(format_args!("package_size={}", package.size));
    args.text_print(format_args!("package_sha2={}", package.sha2));
    args.text_print(format_args!("zip_path={}", zip_path.display()));

    if package.size > MAX_PACKAGE_BYTES {
        return Err(format!(
            "{key}: package too large: {} > {}",
            package.size, MAX_PACKAGE_BYTES
        ));
    }

    let (reused_zip, bytes) = if let Some(bytes) = read_verified_existing_zip(&zip_path, package)? {
        args.text_print(format_args!("reuse_zip=true"));
        (true, bytes)
    } else {
        args.text_print(format_args!("reuse_zip=false"));
        (false, http_get_bytes(&url, package.size + 1)?)
    };
    if bytes.len() as u64 != package.size {
        return Err(format!(
            "{key}: downloaded size mismatch: expected {}, got {}",
            package.size,
            bytes.len()
        ));
    }
    let digest = sha256_hex(&bytes);
    if digest != package.sha2 {
        return Err(format!(
            "{key}: sha256 mismatch: expected {}, got {digest}",
            package.sha2
        ));
    }
    args.text_print(format_args!("verified_sha2={digest}"));

    if args.keep_zip {
        let mut file = File::create(&zip_path)
            .map_err(|error| format!("create {} failed: {error}", zip_path.display()))?;
        file.write_all(&bytes)
            .map_err(|error| format!("write {} failed: {error}", zip_path.display()))?;
    }

    let output_dir = args
        .out_dir
        .join(format!("{}-{}", args.channel.name(), kind.output_name()));
    let extracted = extract_steam_libraries(args, request.library_roots, &bytes, &output_dir)?;
    Ok(JsonPackage {
        package: key,
        url,
        size: package.size,
        sha2: package.sha2.clone(),
        zip_path: zip_path.display().to_string(),
        reused_zip,
        verified_sha2: digest,
        extracted,
    })
}

fn scan_extracted_libraries(args: &Args, packages: &[JsonPackage]) -> (Vec<JsonPatternScan>, bool) {
    let mut libraries = Vec::new();
    for package in packages {
        for extracted in &package.extracted {
            let path = PathBuf::from(&extracted.path);
            let Some(module) = module_from_library_path(&path) else {
                continue;
            };
            let arch_bits = arch_bits_from_library_path(&path).unwrap_or(0);
            libraries.push((module, path, arch_bits));
        }
    }
    libraries.sort_by(|a, b| a.1.cmp(&b.1));

    let mut failed = false;
    let mut scans = Vec::new();
    for (module, path, arch_bits) in libraries {
        if arch_bits == 64 && !args.scan_unsupported {
            args.text_print(format_args!(
                "scan {module} 64-bit: UNSUPPORTED expected_miss path={}",
                path.display()
            ));
            scans.push(JsonPatternScan {
                module: module.to_owned(),
                path: path.display().to_string(),
                arch_bits,
                status: "unsupported",
                expected_miss: true,
                reason: Some("64-bit patterns are not supported yet".to_owned()),
                text_file_off: None,
                text_vaddr: None,
                text_size: None,
                ok_count: 0,
                miss_count: 0,
                failures: Vec::new(),
                entries: Vec::new(),
            });
            continue;
        }

        match scan_module(module, &path) {
            Ok(report) => {
                let fail_count = report.failure_count();
                failed |= fail_count != 0;
                args.text_print(format_args!(
                    "scan {} {}-bit: {} ok={} miss={} failures={} path={}",
                    report.module,
                    report.elf_class.bits(),
                    if fail_count == 0 { "OK" } else { "MISS" },
                    report.ok_count(),
                    report.miss_count(),
                    fail_count,
                    report.path.display()
                ));
                scans.push(json_scan_from_report(report));
            }
            Err(error) => {
                let should_fail = arch_bits != 64 || args.scan_unsupported;
                failed |= should_fail;
                args.text_print(format_args!(
                    "scan {module} {}-bit: FAIL path={} ({error})",
                    arch_bits_label(arch_bits),
                    path.display()
                ));
                scans.push(JsonPatternScan {
                    module: module.to_owned(),
                    path: path.display().to_string(),
                    arch_bits,
                    status: "error",
                    expected_miss: false,
                    reason: Some(error),
                    text_file_off: None,
                    text_vaddr: None,
                    text_size: None,
                    ok_count: 0,
                    miss_count: 1,
                    failures: Vec::new(),
                    entries: Vec::new(),
                });
            }
        }
    }

    (scans, failed)
}

fn module_from_library_path(path: &Path) -> Option<&'static str> {
    match path.file_name()?.to_str()? {
        "steamclient.so" => Some("steamclient"),
        "steamui.so" => Some("steamui"),
        _ => None,
    }
}

fn arch_bits_from_library_path(path: &Path) -> Option<u8> {
    for component in path.components() {
        match component.as_os_str().to_str()? {
            "ubuntu12_32" | "linux32" | "steamrt32" => return Some(32),
            "ubuntu12_64" | "linux64" | "steamrt64" => return Some(64),
            _ => {}
        }
    }
    None
}

fn arch_bits_label(bits: u8) -> String {
    if bits == 0 {
        "unknown".to_owned()
    } else {
        format!("{bits}")
    }
}

fn json_scan_from_report(report: ModuleScanReport) -> JsonPatternScan {
    let arch_bits = report.elf_class.bits();
    let path = report.path.display().to_string();
    let ok_count = report.ok_count();
    let miss_count = report.miss_count();
    let failures = report
        .failures()
        .map(|entry| json_failure(&report, entry))
        .collect();
    let entries = report.entries.iter().map(json_entry).collect();

    JsonPatternScan {
        module: report.module,
        path,
        arch_bits,
        status: "scanned",
        expected_miss: false,
        reason: None,
        text_file_off: Some(report.text_file_off),
        text_vaddr: Some(report.text_vaddr),
        text_size: Some(report.text_size),
        ok_count,
        miss_count,
        failures,
        entries,
    }
}

fn json_failure(report: &ModuleScanReport, entry: &PatternScanEntry) -> JsonPatternFailure {
    JsonPatternFailure {
        module: report.module.clone(),
        path: report.path.display().to_string(),
        arch_bits: report.elf_class.bits(),
        pattern: entry.name.to_owned(),
        status: entry.status.label().to_owned(),
        hits: entry.match_count,
        error: entry.error.clone(),
    }
}

fn json_entry(entry: &PatternScanEntry) -> JsonPatternEntry {
    JsonPatternEntry {
        pattern: entry.name.to_owned(),
        status: entry.status.label().to_owned(),
        hits: entry.match_count,
        target_offset: entry.target_offset,
        error: entry.error.clone(),
    }
}

fn collect_pattern_failures(scans: &[JsonPatternScan]) -> Vec<JsonPatternFailure> {
    scans
        .iter()
        .flat_map(|scan| scan.failures.iter().cloned())
        .collect()
}

fn read_verified_existing_zip(
    zip_path: &Path,
    package: &PackageInfo,
) -> Result<Option<Vec<u8>>, String> {
    if !zip_path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(zip_path)
        .map_err(|error| format!("read {} failed: {error}", zip_path.display()))?;
    if bytes.len() as u64 != package.size {
        return Ok(None);
    }
    if sha256_hex(&bytes) != package.sha2 {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn http_get_string(url: &str, limit: u64) -> Result<String, String> {
    http_agent()
        .get(url)
        .call()
        .map_err(|error| format!("GET {url} failed: {error}"))?
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_string()
        .map_err(|error| format!("read {url} failed: {error}"))
}

fn http_get_bytes(url: &str, limit: u64) -> Result<Vec<u8>, String> {
    http_agent()
        .get(url)
        .call()
        .map_err(|error| format!("GET {url} failed: {error}"))?
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|error| format!("read {url} failed: {error}"))
}

fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(20)))
        .timeout_global(Some(Duration::from_secs(300)))
        .build()
        .new_agent()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn extract_steam_libraries(
    args: &Args,
    library_roots: &[&str],
    zip_bytes: &[u8],
    output_dir: &Path,
) -> Result<Vec<JsonExtractedFile>, String> {
    let cursor = Cursor::new(zip_bytes);
    let mut archive =
        ZipArchive::new(cursor).map_err(|error| format!("open zip failed: {error}"))?;
    let mut extracted = 0usize;
    let mut files = Vec::new();

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|error| format!("read zip entry {index} failed: {error}"))?;
        let Some(enclosed_name) = file.enclosed_name() else {
            continue;
        };
        if !is_steam_library(library_roots, &enclosed_name) {
            continue;
        }

        let out_path = output_dir.join(&enclosed_name);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {} failed: {error}", parent.display()))?;
        }
        let mut out = File::create(&out_path)
            .map_err(|error| format!("create {} failed: {error}", out_path.display()))?;
        std::io::copy(&mut file, &mut out)
            .map_err(|error| format!("extract {} failed: {error}", out_path.display()))?;
        let modified = format!("{:?}", file.last_modified());
        args.text_print(format_args!(
            "extracted={} size={} modified={modified}",
            out_path.display(),
            file.size()
        ));
        files.push(JsonExtractedFile {
            path: out_path.display().to_string(),
            size: file.size(),
            modified,
        });
        extracted += 1;
    }

    if extracted == 0 {
        return Err("zip did not contain steamclient.so or steamui.so".to_owned());
    }

    Ok(files)
}

fn is_steam_library(library_roots: &[&str], path: &Path) -> bool {
    let Some(root) = path
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
    else {
        return false;
    };
    if !library_roots.contains(&root) {
        return false;
    }

    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "steamclient.so" || name == "steamui.so")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parser_reads_nested_root() {
        let manifest = Manifest::parse(
            r#"
            "ubuntu12"
            {
                "version" "1783028805"
                // braces in comments should not end the root: { }
                "bins_steamrt_ubuntu12"
                {
                    "file" "bins_steamrt_ubuntu12.zip.hash"
                    "size" "42"
                    "sha2" "abc"
                }
            }
            "kvsign2"
            {
                "signed" "ignored"
            }
            "#,
        )
        .unwrap();

        let package = manifest.packages.get("bins_steamrt_ubuntu12").unwrap();
        assert_eq!(manifest.version, "1783028805");
        assert_eq!(package.file, "bins_steamrt_ubuntu12.zip.hash");
        assert_eq!(package.size, 42);
        assert_eq!(package.sha2, "abc");
    }

    #[test]
    fn steamrt_package_filters_to_64_bit_libraries() {
        assert!(is_steam_library(
            ROOTS_STEAMRT64,
            Path::new("steamrt64/steamclient.so")
        ));
        assert!(!is_steam_library(
            ROOTS_STEAMRT64,
            Path::new("steamrt32/steamclient.so")
        ));
    }

    #[test]
    fn publicbeta_defaults_to_both_steamrt_roots() {
        let args = Args::parse(["--channel".to_owned(), "publicbeta".to_owned()]).unwrap();
        let requests = args.package_requests();

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].kind.manifest_key(), "bins_steamrt_ubuntu12");
        assert_eq!(requests[0].library_roots, ROOTS_STEAMRT_BOTH);
    }

    #[test]
    fn steamrt_both_roots_accepts_32_and_64_bit_libraries() {
        assert!(is_steam_library(
            ROOTS_STEAMRT_BOTH,
            Path::new("steamrt32/steamclient.so")
        ));
        assert!(is_steam_library(
            ROOTS_STEAMRT_BOTH,
            Path::new("steamrt64/steamui.so")
        ));
    }
}
