use colored::Colorize;

pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!("{}", r#"
  ╔═══════════════════════════════════════╗
  ║              A B Y S S               ║
  ║   offline forensic analysis engine   ║
  ╚═══════════════════════════════════════╝"#.bold().red());
    println!("  {}\n", format!("v{version}").dimmed());
}
