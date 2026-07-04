use std::path::PathBuf;

use vapor_forge_config::RuntimeConfig;

fn main() {
    if let Err(error) = run() {
        eprintln!("vapor-forge-config-check: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(std::env::args().skip(1))?;
    let text = std::fs::read_to_string(&args.config_path)
        .map_err(|error| format!("read {} failed: {error}", args.config_path.display()))?;
    let dry_run = RuntimeConfig::sync_default_template_dry_run(&text)
        .map_err(|error| format!("template sync dry-run failed: {error}"))?;
    let config = toml::from_str::<RuntimeConfig>(&dry_run.synced)
        .map_err(|error| format!("synced config parse failed: {error}"))?;

    if args.format == OutputFormat::Json {
        let output = JsonOutput {
            config_path: args.config_path.display().to_string(),
            would_change: dry_run.changed,
            auto_added_fields: dry_run.added_fields,
            kept_commented_examples: dry_run.kept_commented_examples,
            pruned_commented_examples: dry_run.pruned_commented_examples,
            final_config_debug: format!("{config:#?}"),
            synced_toml: args.show_synced.then_some(dry_run.synced),
        };
        let json = serde_json::to_string_pretty(&output)
            .map_err(|error| format!("serialize JSON failed: {error}"))?;
        println!("{json}");
        return Ok(());
    }

    println!("config_path={}", args.config_path.display());
    println!("would_change={}", dry_run.changed);

    print_list("auto_added_fields", &dry_run.added_fields);
    print_list("kept_commented_examples", &dry_run.kept_commented_examples);
    print_list(
        "pruned_commented_examples",
        &dry_run.pruned_commented_examples,
    );

    println!("final_config:");
    println!("{config:#?}");

    if args.show_synced {
        println!("synced_toml:");
        print!("{}", dry_run.synced);
    }

    Ok(())
}

struct Args {
    config_path: PathBuf,
    show_synced: bool,
    format: OutputFormat,
}

#[derive(Eq, PartialEq)]
enum OutputFormat {
    Text,
    Json,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut config_path = None;
        let mut show_synced = false;
        let mut format = OutputFormat::Text;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--config" => config_path = Some(PathBuf::from(next_value(&mut args, "--config")?)),
                "--show-synced" => show_synced = true,
                "--format" => {
                    let value = next_value(&mut args, "--format")?;
                    format = match value.as_str() {
                        "text" => OutputFormat::Text,
                        "json" => OutputFormat::Json,
                        other => return Err(format!("unsupported format {other:?}\n{}", usage())),
                    };
                }
                "-h" | "--help" => return Err(usage()),
                other if other.starts_with('-') => {
                    return Err(format!("unknown argument {other:?}\n{}", usage()));
                }
                path => {
                    if config_path.is_some() {
                        return Err(format!("multiple config paths provided\n{}", usage()));
                    }
                    config_path = Some(PathBuf::from(path));
                }
            }
        }

        Ok(Self {
            config_path: config_path.unwrap_or_else(|| PathBuf::from("config.toml")),
            show_synced,
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
        "usage: vapor-forge-config-check [--config PATH] [--show-synced] ",
        "[--format text|json] [PATH]\n",
        "\n",
        "Reads a config.toml, dry-runs template sync, and prints the parsed final config."
    )
    .to_owned()
}

#[derive(serde::Serialize)]
struct JsonOutput {
    config_path: String,
    would_change: bool,
    auto_added_fields: Vec<String>,
    kept_commented_examples: Vec<String>,
    pruned_commented_examples: Vec<String>,
    final_config_debug: String,
    synced_toml: Option<String>,
}

fn print_list(label: &str, values: &[String]) {
    println!("{label}:");
    if values.is_empty() {
        println!("  (none)");
    } else {
        for value in values {
            println!("  - {value}");
        }
    }
}
