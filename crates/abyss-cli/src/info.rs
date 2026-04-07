use abyss_output::collector::{Collector, OutputFormat};
use abyss_target::Target;
use std::path::Path;

pub fn run(path: &str, output_format: OutputFormat) -> i32 {
    let target = match Target::open(Path::new(path)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error opening target: {}", e);
            return 2;
        }
    };
    let mut collector = Collector::new(output_format);
    collector.add(target.info());
    if let Err(e) = collector.emit(&mut std::io::stdout()) {
        eprintln!("Error writing output: {}", e);
        return 2;
    }
    0
}
