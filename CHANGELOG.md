# Changelog

All notable changes to Abyss will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Initial release
- 13-crate Cargo workspace
- Disk image support: Raw, E01 (EnCase), VMDK (VMware)
- Partition support: MBR, GPT
- Filesystem support: NTFS, ext2/3/4
- Credential extraction: SAM, NTDS.dit, LSA, DCC2, DPAPI, browsers, SSH, cloud
- Memory analysis: LSASS minidumps, MSV1_0, Wdigest
- Persistence detection: services, BootExecute, IFEO
- Output formats: text, JSON, Hashcat
- Interactive filesystem shell
