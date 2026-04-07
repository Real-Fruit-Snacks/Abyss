<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Abyss/master/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Abyss/master/docs/assets/logo-light.svg">
  <img alt="Abyss" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Abyss/master/docs/assets/logo-dark.svg" width="520">
</picture>

![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Offensive disk, memory, and Active Directory analysis framework.**

Extract credentials, keys, and persistence mechanisms from forensic disk images and memory dumps. SAM hashes, NTDS.dit domain dumps, LSA secrets, DPAPI keys, browser passwords, SSH keys, cloud credentials, and LSASS minidumps. Raw, E01, and VMDK formats with NTFS and ext4 support.

> **Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.
>
> **Under Active Development**: Core functionality works but parsers are being validated against real-world artifacts. Expect breaking changes before v1.0.

</div>

---

## Quick Start

**Prerequisites:** Rust 1.70+

```bash
git clone https://github.com/Real-Fruit-Snacks/Abyss.git
cd Abyss
cargo build --release
```

**Analyze a disk image:**

```bash
abyss image disk.img                    # full analysis
abyss image disk.img --creds            # credentials only
abyss image disk.img --output hashcat   # hashcat-ready output
```

---

## Features

### Credential Extraction

SAM hashes, NTDS.dit domain dumps (PEK v2 RC4 + v3 AES), LSA secrets, cached domain credentials (DCC2), DPAPI master keys.

```bash
abyss image disk.img --creds
abyss image disk.img --output hashcat   # mode 1000, 2100, shadow
```

### Browser Passwords

Chromium saved passwords via DPAPI decryption. Firefox via key4.db + logins.json.

```bash
abyss image disk.img --filter browser_credential
```

### Memory Analysis

LSASS minidump credential extraction. MSV1_0/NTLM credential packages. Wdigest plaintext scanning.

```bash
abyss memory lsass.dmp
```

### Disk Image Formats

Raw sector dumps, E01 (EnCase), and VMDK (VMware sparse). Auto-detected by header.

```bash
abyss image evidence.E01
abyss image server.vmdk
```

### SSH and Cloud Keys

Private keys, authorized_keys, host keys. AWS, Azure, GCP, GitHub, Docker, Kubernetes, Terraform credentials.

```bash
abyss image disk.img --keys
```

### Persistence Detection

Windows services, BootExecute entries, Image File Execution Options debugger hijacks.

```bash
abyss image disk.img --persist
```

### Interactive Shell

Filesystem browser for manual investigation. List, cat, hexdump, hash, and extract files.

```bash
abyss shell disk.img
```

### Output Formats

Text (colored), JSON (line-delimited), and Hashcat (modes 1000, 2100, shadow auto-detect).

```bash
abyss image disk.img --output json --filter sam_hash,ntds_hash
```

---

## Architecture

```
crates/
├── abyss-cli/        # Command-line interface
├── abyss-container/   # Disk image containers (Raw, E01, VMDK)
├── abyss-volume/      # Partition tables (MBR, GPT)
├── abyss-ntfs/        # NTFS filesystem parser
├── abyss-extfs/       # ext2/3/4 filesystem parser
├── abyss-registry/    # Windows registry hive parser
├── abyss-ese/         # ESE/JET database parser (NTDS.dit)
├── abyss-crypto/      # Credential decryption (SAM, LSA, NTDS, DPAPI)
├── abyss-browser/     # Browser credential extraction
├── abyss-memory/      # Memory dump analysis (LSASS)
├── abyss-target/      # Extraction pipeline orchestration
├── abyss-output/      # Finding types and output formatters
└── abyss-cstruct/     # Binary struct parsing primitives
```

Pipeline architecture: Disk Image to Container (Raw/E01/VMDK) to Volume (MBR/GPT) to Filesystem (NTFS/ext4) to Extractors to Findings to Output. 13-crate Cargo workspace with each crate owning a single responsibility.

---

## Platform Support

| | Linux | Windows |
|---|---|---|
| Disk Image Analysis | Full | Full |
| Memory Analysis | Full | Full |
| NTFS Parsing | Full | Full |
| ext4 Parsing | Full | Full |
| Interactive Shell | Full | Full |
| Hashcat Output | Full | Full |

---

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Abyss/security/advisories). 90-day responsible disclosure.

**Abyss does not:**
- Modify source disk images (read-only analysis)
- Provide remote access or C2 capabilities (not an implant)
- Crack extracted hashes (use Hashcat for that)
- Automatically scrub credentials from process memory

---

## License

[MIT](LICENSE) — Copyright 2026 Real-Fruit-Snacks
