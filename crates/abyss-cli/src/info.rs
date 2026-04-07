use abyss_output::collector::{Collector, OutputFormat};
use abyss_target::Target;
use std::path::Path;

pub fn run(path: &str, output_format: OutputFormat, quiet: bool) -> i32 {
    if !quiet { eprintln!("[*] Opening image: {}", path); }
    let target = match Target::open(Path::new(path)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error opening '{}': {}", path, e);
            return 2;
        }
    };
    if !quiet { eprintln!("[+] Image opened successfully"); }
    let mut collector = Collector::new(output_format);
    collector.add(target.info());
    if let Err(e) = collector.emit(&mut std::io::stdout()) {
        eprintln!("Error writing output: {}", e);
        return 2;
    }
    0
}
