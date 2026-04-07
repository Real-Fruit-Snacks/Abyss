use abyss_memory::minidump::MinidumpReader;
use abyss_memory::lsass::extract_lsass_credentials;
use abyss_output::collector::{Collector, OutputFormat};
use abyss_output::finding::{Finding, MemoryCredentialFinding, hex_encode};

use std::fs::File;
use std::io::BufReader;

pub fn run(path: &str, output_format: OutputFormat, quiet: bool) -> i32 {
    if !quiet { eprintln!("[*] Opening memory dump: {}", path); }
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening file: {}", e);
            return 2;
        }
    };

    let reader = BufReader::new(file);
    let mut dump = match MinidumpReader::open(Box::new(reader)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error parsing memory dump: {}", e);
            return 2;
        }
    };

    if !quiet {
        eprintln!("[+] Memory dump parsed");
        eprintln!(
            "  Dump: arch={:?}, build={}, modules={}, memory_ranges={}",
            dump.arch,
            dump.os_build,
            dump.modules().len(),
            dump.memory_ranges().len()
        );
        eprintln!("[*] Extracting credentials...");
    }

    let credentials = match extract_lsass_credentials(&mut dump) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error extracting credentials: {}", e);
            return 2;
        }
    };

    let mut collector = Collector::new(output_format);

    for cred in &credentials {
        collector.add(Finding::MemoryCredential(MemoryCredentialFinding {
            provider: cred.provider.clone(),
            domain: cred.domain.clone(),
            username: cred.username.clone(),
            password: cred.password.clone(),
            nt_hash: cred.nt_hash.as_ref().map(|h| hex_encode(h)),
        }));
    }

    if !quiet {
        if collector.is_empty() {
            eprintln!("[-] No credentials found in memory dump.");
        } else {
            eprintln!("[+] Extraction complete: {} findings", collector.count());
        }
    }

    if let Err(e) = collector.emit(&mut std::io::stdout()) {
        eprintln!("Error writing output: {}", e);
        return 2;
    }

    0
}
