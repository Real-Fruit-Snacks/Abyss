<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Abyss/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Abyss/main/docs/assets/logo-light.svg">
  <img alt="Abyss" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Abyss/main/docs/assets/logo-dark.svg" width="100%">
</picture>

> [!IMPORTANT]
> **Offensive disk, memory, and Active Directory analysis framework.** Extract credentials, keys, and persistence mechanisms from forensic disk images and memory dumps. SAM hashes, NTDS.dit domain dumps, LSA secrets, DPAPI keys, browser passwords, SSH keys, cloud credentials, and LSASS minidumps with support for Raw, E01, and VMDK formats.

> *An abyss is a deep, dark void where things disappear and are seemingly lost forever. Felt fitting for a tool that dives into the depths of forensic images to extract hidden secrets and credentials that would otherwise remain buried in digital darkness.*

---

## §1 / Premise

Abyss is a **Rust-built forensic analysis framework** designed to extract actionable intelligence from disk images and memory dumps. Point it at forensic evidence and it systematically extracts credentials, keys, persistence mechanisms, and other security-relevant artifacts across Windows and Linux filesystems.

The framework handles the entire analysis pipeline — from parsing disk image containers (Raw, E01, VMDK) through filesystem analysis (NTFS, ext4) to credential extraction and decryption. Native Rust implementations provide high-performance parsing without external tool dependencies. Results export to multiple formats including Hashcat-ready hashes for immediate password cracking workflows.

**Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.

---

## §2 / Specs

| KEY        | VALUE                                                                       |
|------------|-----------------------------------------------------------------------------|
| **EXTRACTION** | **SAM hashes · NTDS.dit domain dumps · LSA secrets · DPAPI keys · cached credentials (DCC2)** |
| **BROWSERS**   | **Chromium passwords via DPAPI · Firefox via key4.db + logins.json** |
| **MEMORY**     | **LSASS minidump analysis · MSV1_0/NTLM packages · Wdigest plaintext scanning** |
| **IMAGES**     | **Raw sector dumps · E01 (EnCase) · VMDK (VMware) with header auto-detection** |
| **KEYS**       | **SSH private/host keys · AWS/Azure/GCP · GitHub/Docker/Kubernetes/Terraform credentials** |
| **PERSISTENCE** | **Windows services · BootExecute · IFEO debugger hijacks · startup analysis** |
| **FILESYSTEMS** | **NTFS + ext2/3/4 with full partition table support (MBR/GPT)** |
| **OUTPUT**     | **Colored text · JSON (line-delimited) · Hashcat modes 1000/2100/shadow** |
| **PLATFORM**   | **Linux + Windows full support · interactive shell · read-only analysis** |
| **STACK**      | **Pure Rust 1.70+ · 13-crate Cargo workspace · zero external dependencies** |

---

## §3 / Quickstart

**Prerequisites:** Rust 1.70+

```bash
git clone https://github.com/Real-Fruit-Snacks/Abyss.git
cd Abyss
cargo build --release

# Full disk image analysis
abyss image disk.img

# Credentials only extraction
abyss image disk.img --creds

# Memory dump analysis
abyss memory lsass.dmp

# Hashcat-ready output
abyss image disk.img --output hashcat

# Interactive filesystem shell
abyss shell disk.img
```

---

## §4 / Reference

```bash
# DISK IMAGE ANALYSIS
abyss image <path>                    # Full analysis of disk image
abyss image <path> --creds            # Extract credentials only
abyss image <path> --keys             # Extract SSH and cloud keys
abyss image <path> --persist          # Find persistence mechanisms

# MEMORY ANALYSIS  
abyss memory <dump>                   # Analyze LSASS memory dump
abyss memory <dump> --output json     # JSON output format

# FILTERING & OUTPUT
abyss image <path> --filter sam_hash,ntds_hash     # Specific artifact types
abyss image <path> --output hashcat               # Hashcat format
abyss image <path> --output json                  # JSON line-delimited

# INTERACTIVE ANALYSIS
abyss shell <image>                   # Interactive filesystem browser
  ls, cd, cat, hexdump, hash, extract # Shell commands available

# SUPPORTED FORMATS
abyss image evidence.E01              # EnCase E01 format
abyss image server.vmdk               # VMware disk image
abyss image disk.raw                  # Raw sector dump

# ARTIFACT TYPES (--filter)
sam_hash, ntds_hash, lsa_secret, dpapi_key, browser_credential,
ssh_key, cloud_credential, service_persistence, boot_execute,
ifeo_hijack, cached_credential
```

---

## §5 / Architecture

**Pipeline Architecture**: Disk Image → Container Parser → Volume Parser → Filesystem Parser → Extractors → Findings → Output Formatters

```
crates/
├── abyss-cli/        # Command-line interface and argument parsing
├── abyss-container/  # Container parsers (Raw, E01, VMDK)
├── abyss-volume/     # Partition tables (MBR, GPT) and volume analysis
├── abyss-ntfs/       # NTFS filesystem parser and file extraction
├── abyss-extfs/      # ext2/3/4 filesystem parser
├── abyss-registry/   # Windows registry hive parser (SAM, SYSTEM, SOFTWARE)
├── abyss-ese/        # ESE/JET database parser for NTDS.dit
├── abyss-crypto/     # Credential decryption (SAM, LSA, NTDS, DPAPI)
├── abyss-browser/    # Browser credential extraction (Chrome, Firefox)
├── abyss-memory/     # Memory dump analysis and LSASS parsing
├── abyss-target/     # Extraction pipeline orchestration
├── abyss-output/     # Finding types and output formatters
└── abyss-cstruct/    # Binary struct parsing primitives
```

**13-crate Cargo workspace** with each crate owning single responsibility. Native Rust implementations avoid external process dependencies and provide high-performance parsing with memory safety guarantees.

---

## §6 / Authorization

Abyss is designed for **authorized forensic analysis and incident response** with proper legal authorization. Use only on disk images and memory dumps you own or have explicit written permission to analyze.

Security vulnerabilities should be reported via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Abyss/security/advisories) with 90-day responsible disclosure.

**Abyss does not**: modify source images (read-only), provide remote access capabilities, crack extracted hashes automatically, or scrub credentials from memory.

---

**Real-Fruit-Snacks** — [All projects](https://real-fruit-snacks.github.io/) · [Security](https://github.com/Real-Fruit-Snacks/Abyss/security/advisories) · [License](LICENSE)