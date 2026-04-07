use abyss_output::collector::{Collector, OutputFormat};
use abyss_target::{ExtractFilter, Target};
use std::path::Path;

pub fn run(
    path: &str,
    creds: bool,
    keys: bool,
    persist: bool,
    all: bool,
    output_format: OutputFormat,
) -> i32 {
    let mut target = match Target::open(Path::new(path)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error opening target: {}", e);
            return 2;
        }
    };
    let mut collector = Collector::new(output_format);
    collector.add(target.info());

    let filter = ExtractFilter::from_flags(creds, keys, persist, all);
    target.extract_filtered(&mut collector, &filter);

    if let Err(e) = collector.emit(&mut std::io::stdout()) {
        eprintln!("Error writing output: {}", e);
        return 2;
    }
    0
}
