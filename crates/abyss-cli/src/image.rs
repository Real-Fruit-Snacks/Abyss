use abyss_output::collector::{Collector, OutputFormat};
use abyss_target::{ExtractFilter, Target};
use std::path::Path;

pub fn run(
    path: &str,
    creds: bool,
    keys: bool,
    persist: bool,
    all: bool,
    filter: Option<&str>,
    output_format: OutputFormat,
    quiet: bool,
) -> i32 {
    if !quiet { eprintln!("[*] Opening image: {}", path); }
    let mut target = match Target::open(Path::new(path)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error opening '{}': {}", path, e);
            return 2;
        }
    };

    if !quiet {
        eprintln!("[+] OS detected: {}", target.os);
        eprintln!("[+] Partitions: {}", target.partitions.len());
        if let Some(fs_type) = target.filesystem_type() {
            eprintln!("[+] Filesystem: {}", fs_type);
        } else {
            eprintln!("[-] No supported filesystem found");
        }
    }

    let mut collector = Collector::new(output_format);
    collector.add(target.info());

    let extract_filter = ExtractFilter::from_flags(creds, keys, persist, all);
    if !quiet { eprintln!("[*] Running extractors..."); }
    target.extract_filtered(&mut collector, &extract_filter);

    if let Some(type_filter) = filter {
        let types: Vec<&str> = type_filter.split(',').map(|s| s.trim()).collect();
        collector.filter_by_types(&types);
    }

    if !quiet { eprintln!("[+] Extraction complete: {} findings", collector.count()); }

    if let Err(e) = collector.emit(&mut std::io::stdout()) {
        eprintln!("Error writing output: {}", e);
        return 2;
    }
    0
}
