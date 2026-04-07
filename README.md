# Abyss

> **Status: Under Active Development** — Core functionality works but parsers are being validated against real-world forensic artifacts. NTDS.dit hash extraction from Server 2016+ databases is in progress. Expect breaking changes before v1.0.

Offensive disk, memory, and Active Directory analysis framework written in Rust.

Abyss extracts credentials, keys, and persistence mechanisms from forensic disk images and memory dumps — fast, offline, and without external dependencies.

## Features

### Disk Image Formats
- **Raw** — bare sector dumps
- **E01** (EnCase) — auto-detected
- **VMDK** (VMware sparse) — auto-detected

### Partition Schemes
- MBR and GPT — auto-detected

### Filesystems
- NTFS
- ext2/3/4

### Credential Extraction
- **Windows SAM** — NTLM and LM hashes for local accounts
- **LSA Secrets** — service account passwords, cached tokens
- **Cached Domain Credentials** — DCC2 hashes (mode 2100)
- **DPAPI Master Keys** — Windows Data Protection API keys
- **Active Directory (NTDS.dit)** — full domain hash dump with password history (PEK v2 RC4 + v3 AES)
- **Browser — Chromium** — saved passwords via DPAPI decryption
- **Browser — Firefox** — saved passwords via key4.db + logins.json
- **Linux /etc/shadow and /etc/passwd** — all shadow entries
- **Service credentials** — credentials embedded in service configs
- **SSH** — private keys, authorized_keys, host keys
- **Cloud** — AWS, Azure, GCP, GitHub, Docker, Kubernetes, Terraform, git credentials

### Memory Analysis
- LSASS minidump credential extraction
- MSV1_0 / NTLM credential packages
- Wdigest plaintext credential scanning

### Persistence
- Windows services
- BootExecute entries
- Image File Execution Options (IFEO) debugger hijacks

### Output
- **Text** — human-readable colored output
- **JSON** — line-delimited, one finding per line
- **Hashcat** — ready-to-crack format for modes 1000, 2100, and shadow auto-detection

---

## Installation

### From source
```bash
git clone https://github.com/Real-Fruit-Snacks/abyss.git
cd abyss
cargo build --release
```

The binary will be at `target/release/abyss` (or `abyss.exe` on Windows).

### Requirements
- Rust 1.70+ (for building from source)
- No runtime dependencies

---

## Usage

### Analyze a disk image
```bash
# Full analysis (all extractors)
abyss image disk.img

# Extract only credentials
abyss image disk.img --creds

# Extract only SSH/cloud keys
abyss image disk.img --keys

# Extract only persistence mechanisms
abyss image disk.img --persist

# JSON output for processing
abyss image disk.img --output json

# Hashcat-compatible output
abyss image disk.img --output hashcat

# Filter specific finding types
abyss image disk.img --filter sam_hash,ntds_hash

# Quiet mode (suppress banner and progress)
abyss image disk.img --quiet

# Verbose logging
abyss image disk.img --verbose
```

### Analyze E01 or VMDK images
```bash
# E01 (EnCase) images — auto-detected by header
abyss image evidence.E01

# VMDK (VMware) images — auto-detected by header
abyss image server.vmdk
```

### Analyze memory dumps
```bash
# Extract credentials from LSASS minidump
abyss memory lsass.dmp
```

### Interactive filesystem shell
```bash
abyss shell disk.img
```

Shell commands:

| Command | Description |
|---------|-------------|
| `ls [path]` | List directory contents |
| `cat <path>` | Print file contents |
| `hexdump <path>` | Hex dump (first 512 bytes) |
| `hash <path>` | Compute MD5 + SHA-256 |
| `save <src> <dst>` | Extract file to local disk |
| `info` | Display target metadata |
| `volumes` | List partitions |

### Display image metadata
```bash
abyss info disk.img
```

---

## Architecture

Abyss is a modular Rust workspace with 13 crates:

| Crate | Purpose |
|-------|---------|
| `abyss-cli` | Command-line interface |
| `abyss-cstruct` | Binary struct parsing primitives |
| `abyss-container` | Disk image containers (Raw, E01, VMDK) |
| `abyss-volume` | Partition table parsing (MBR, GPT) |
| `abyss-ntfs` | NTFS filesystem parser |
| `abyss-extfs` | ext2/3/4 filesystem parser |
| `abyss-registry` | Windows registry hive parser |
| `abyss-ese` | ESE/JET database parser (NTDS.dit) |
| `abyss-crypto` | Credential decryption (SAM, LSA, NTDS, DPAPI) |
| `abyss-browser` | Browser credential extraction (Chromium, Firefox) |
| `abyss-memory` | Memory dump analysis (minidumps, LSASS) |
| `abyss-target` | Target abstraction and extraction pipeline |
| `abyss-output` | Finding types and output formatters |

### Pipeline

```
Disk Image → Container (Raw/E01/VMDK)
  → Volume (MBR/GPT)
    → Filesystem (NTFS/ext4)
      → Extractors → Findings → Output
```

---

## Output Formats

### Text (default)
Human-readable colored output with `[SAM]`, `[NTDS]`, `[LSA]`, `[BROWSER]`, etc. prefixes.

### JSON (`--output json`)
Line-delimited JSON — one finding per line with a `type` discriminator:
```json
{"type":"sam_hash","username":"Administrator","rid":500,"nt_hash":"aad3b435b51404eeaad3b435b51404ee","lm_hash":"aad3b435b51404eeaad3b435b51404ee"}
{"type":"ntds_hash","username":"jsmith","rid":1105,"nt_hash":"8846f7eaee8fb117ad06bdd830b7586c","lm_hash":"aad3b435b51404eeaad3b435b51404ee"}
{"type":"browser_credential","browser":"Chrome","url":"https://example.com","username":"user@example.com","password":"hunter2"}
```

### Hashcat (`--output hashcat`)
Ready for cracking:
- SAM/NTDS hashes — mode 1000 (`username:rid:lm_hash:nt_hash:::`)
- Cached domain credentials — mode 2100 (`$DCC2$iterations#username#hash`)
- Shadow entries — auto-detected mode based on hash prefix (`$1$`, `$6$`, etc.)

---

## Finding Types

Use with `--filter` (comma-separated) to restrict output to specific finding types:

| Type | Description |
|------|-------------|
| `target_info` | System metadata (always included) |
| `sam_hash` | Windows SAM hashes |
| `ntds_hash` | NTDS.dit domain hashes |
| `lsa_secret` | LSA secrets |
| `dcc2` | Cached domain credentials |
| `dpapi_master_key` | DPAPI master keys |
| `browser_credential` | Browser saved passwords |
| `ssh_private_key` | SSH private keys |
| `ssh_authorized_key` | SSH authorized_keys entries |
| `shadow_entry` | Linux /etc/shadow entries |
| `service_credential` | Service account credentials |
| `persistence_entry` | Persistence mechanisms |
| `cloud_credential` | Cloud provider credentials |
| `memory_credential` | Memory dump credentials |

---

## Security Considerations

- **This is an offensive tool.** Only use on systems you own or have explicit written authorization to analyze.
- Extracted credentials are printed to stdout. Pipe to a file and protect it with appropriate permissions.
- The tool operates read-only on disk images — it never modifies the source image.
- Decrypted credentials are held in process memory until exit. No automatic scrubbing is performed.
- Firefox profiles protected by a master password will be detected and skipped with a warning.

---

## License

MIT
