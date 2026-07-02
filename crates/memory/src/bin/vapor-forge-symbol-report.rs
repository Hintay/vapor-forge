use vapor_forge_memory::{
    analyze_public_dynamic_symbol_questions, summarize_elf_file, ElfMetadataLimits,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("vapor-forge-symbol-report: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut paths = std::env::args().skip(1).collect::<Vec<_>>();
    if paths.is_empty() {
        return Err(
            "usage: vapor-forge-symbol-report <steamui.so|steamclient.so> [...]".to_owned(),
        );
    }

    paths.sort();
    for path in paths {
        let summary = summarize_elf_file(
            &path,
            ElfMetadataLimits {
                max_dynamic_symbol_names: 64,
                ..ElfMetadataLimits::default()
            },
        )
        .map_err(|error| error.to_string())?;

        println!("module={}", summary.name);
        println!("path={}", summary.path);
        println!("class={}", summary.elf_class);
        println!("arch={}", summary.architecture);
        println!("dynamic_symbol_count={}", summary.dynamic_symbol_count);
        println!("sample_symbol_count={}", summary.dynamic_symbol_names.len());
        println!(
            "sample_truncated={}",
            summary.dynamic_symbol_names_truncated
        );
        println!("build_id={}", summary.build_id.as_deref().unwrap_or("none"));

        for result in analyze_public_dynamic_symbol_questions(&summary) {
            println!(
                "question id={} answer={} detail={}",
                result.id, result.answer, result.detail
            );
        }

        for symbol in summary.dynamic_symbol_names {
            println!("sample_symbol={symbol}");
        }
    }

    Ok(())
}
