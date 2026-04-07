use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use abyss_container::raw::RawContainer;
use abyss_container::traits::ContainerParser;
use abyss_cstruct::read::ReadSeek;
use abyss_ntfs::NtfsFilesystem;
use abyss_output::collector::Collector;
use abyss_output::finding::{FilesystemInfo, Finding, TargetInfoFinding, VolumeInfo};
use abyss_volume::{discover_partitions, Partition};

use crate::detect::OsType;
use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};
use crate::extractors::{BrowserExtractor, CachedCredsExtractor, DpapiExtractor, LinuxCredsExtractor, LsaExtractor, SamExtractor, SshExtractor};

/// Internal reader that provides Read+Seek access to a slice of a file.
struct PartitionReader {
    inner: BufReader<File>,
    base_offset: u64,
    size: u64,
    position: u64,
}

impl PartitionReader {
    fn new(file: File, base_offset: u64, size: u64) -> Self {
        Self {
            inner: BufReader::new(file),
            base_offset,
            size,
            position: 0,
        }
    }
}

impl Read for PartitionReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.size.saturating_sub(self.position);
        if remaining == 0 {
            return Ok(0);
        }
        let max = buf.len().min(remaining as usize);
        let n = self.inner.read(&mut buf[..max])?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for PartitionReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                (self.size as i64 + offset).max(0) as u64
            }
            SeekFrom::Current(offset) => {
                (self.position as i64 + offset).max(0) as u64
            }
        };
        let clamped = new_pos.min(self.size);
        self.inner.seek(SeekFrom::Start(self.base_offset + clamped))?;
        self.position = clamped;
        Ok(clamped)
    }
}

/// Opened target disk image with OS detection and filesystem discovery.
pub struct Target {
    pub os: OsType,
    pub hostname: Option<String>,
    pub version: Option<String>,
    pub domain: Option<String>,
    pub partitions: Vec<Partition>,
    pub ntfs: Option<NtfsFilesystem>,
}

impl Target {
    /// Open a disk image at `path`, discover partitions, and probe filesystems.
    pub fn open(path: &Path) -> Result<Self, TargetError> {
        let file = File::open(path).map_err(|e| TargetError::OpenFailed {
            detail: e.to_string(),
        })?;

        // Wrap in RawContainer via ContainerParser
        let reader: Box<dyn ReadSeek> = Box::new(BufReader::new(
            File::open(path).map_err(|e| TargetError::OpenFailed {
                detail: e.to_string(),
            })?,
        ));
        let mut _container = RawContainer::open(reader)?;

        // Open a fresh reader for partition discovery
        let mut disc_reader = BufReader::new(
            File::open(path).map_err(|e| TargetError::OpenFailed {
                detail: e.to_string(),
            })?,
        );

        let partitions = match discover_partitions(&mut disc_reader, 512u64) {
            Ok(parts) => parts,
            Err(_) => Vec::new(),
        };

        let mut os = OsType::Unknown;
        let mut ntfs: Option<NtfsFilesystem> = None;

        if partitions.is_empty() {
            // Try treating the whole image as a filesystem
            let part_file = File::open(path).map_err(|e| TargetError::OpenFailed {
                detail: e.to_string(),
            })?;
            let size = part_file.metadata().map(|m| m.len()).unwrap_or(0);
            let mut part_reader: Box<dyn ReadSeek> =
                Box::new(PartitionReader::new(part_file, 0, size));
            if NtfsFilesystem::probe(&mut part_reader) {
                // Re-open for actual open
                let part_file2 = File::open(path).map_err(|e| TargetError::OpenFailed {
                    detail: e.to_string(),
                })?;
                let size2 = part_file2.metadata().map(|m| m.len()).unwrap_or(0);
                let reader2: Box<dyn ReadSeek> =
                    Box::new(PartitionReader::new(part_file2, 0, size2));
                match NtfsFilesystem::open(reader2) {
                    Ok(fs) => {
                        os = OsType::Windows;
                        ntfs = Some(fs);
                    }
                    Err(e) => {
                        log::debug!("NTFS open failed on whole image: {}", e);
                    }
                }
            }
        } else {
            for partition in &partitions {
                let part_file = File::open(path).map_err(|e| TargetError::OpenFailed {
                    detail: e.to_string(),
                })?;
                let mut part_reader: Box<dyn ReadSeek> = Box::new(PartitionReader::new(
                    part_file,
                    partition.offset,
                    partition.size,
                ));
                if NtfsFilesystem::probe(&mut part_reader) {
                    // Re-open for actual open
                    let part_file2 = File::open(path).map_err(|e| TargetError::OpenFailed {
                        detail: e.to_string(),
                    })?;
                    let reader2: Box<dyn ReadSeek> = Box::new(PartitionReader::new(
                        part_file2,
                        partition.offset,
                        partition.size,
                    ));
                    match NtfsFilesystem::open(reader2) {
                        Ok(fs) => {
                            os = OsType::Windows;
                            ntfs = Some(fs);
                            break;
                        }
                        Err(e) => {
                            log::debug!("NTFS open failed on partition {}: {}", partition.index, e);
                        }
                    }
                }
            }
        }

        // Suppress unused variable warning — file is opened above for size
        let _ = file;

        Ok(Target {
            os,
            hostname: None,
            version: None,
            domain: None,
            partitions,
            ntfs,
        })
    }

    /// Returns true if any filesystem was successfully opened.
    pub fn has_filesystem(&self) -> bool {
        self.ntfs.is_some()
    }

    /// Build the extraction context by loading registry hives from the NTFS filesystem.
    fn build_extraction_context(&mut self) -> Result<ExtractionContext, TargetError> {
        let mut ctx = ExtractionContext::new();

        if self.os != OsType::Windows {
            return Ok(ctx);
        }

        let hive_paths = [
            ("SYSTEM", "Windows/System32/config/SYSTEM"),
            ("SAM", "Windows/System32/config/SAM"),
            ("SECURITY", "Windows/System32/config/SECURITY"),
        ];

        if let Some(ref mut ntfs) = self.ntfs {
            for (name, path) in &hive_paths {
                match ntfs.read_file(path) {
                    Ok(data) => {
                        let cursor = std::io::Cursor::new(data);
                        match abyss_registry::RegistryHive::open(Box::new(cursor)) {
                            Ok(hive) => {
                                log::info!("Opened {} hive from {}", name, path);
                                match *name {
                                    "SYSTEM" => ctx.system_hive = Some(hive),
                                    "SAM" => ctx.sam_hive = Some(hive),
                                    "SECURITY" => ctx.security_hive = Some(hive),
                                    _ => {}
                                }
                            }
                            Err(e) => log::warn!("Failed to parse {} hive: {}", name, e),
                        }
                    }
                    Err(e) => log::debug!("Could not read {}: {}", path, e),
                }
            }

            // Discover users from Windows Users/ directory
            if let Ok(users_idx) = ntfs.find_file("Users") {
                if let Ok(entries) = ntfs.list_directory(users_idx) {
                    for (name, _is_dir, _idx) in entries {
                        if !name.is_empty()
                            && name != "."
                            && name != ".."
                            && name != "Public"
                            && name != "Default"
                            && name != "Default User"
                            && name != "All Users"
                        {
                            ctx.discovered_users.push(name);
                        }
                    }
                }
            }

            // Discover users from Linux home/ directory
            if let Ok(home_idx) = ntfs.find_file("home") {
                if let Ok(entries) = ntfs.list_directory(home_idx) {
                    for (name, _is_dir, _idx) in entries {
                        if !name.is_empty() && name != "." && name != ".." {
                            if !ctx.discovered_users.contains(&name) {
                                ctx.discovered_users.push(name);
                            }
                        }
                    }
                }
            }

            // Read SSH private key and authorized_keys files for known users
            let mut ssh_paths: Vec<String> = Vec::new();
            let candidate_users: Vec<String> = {
                let mut v = ctx.discovered_users.clone();
                for common in &["Administrator", "admin", "user", "root", "ubuntu", "ec2-user"] {
                    let s = common.to_string();
                    if !v.contains(&s) {
                        v.push(s);
                    }
                }
                v
            };
            for user in &candidate_users {
                let prefixes: Vec<String> = if user == "root" {
                    vec!["root/.ssh".to_string(), "home/root/.ssh".to_string()]
                } else {
                    vec![
                        format!("Users/{}/.ssh", user),
                        format!("home/{}/.ssh", user),
                    ]
                };
                for prefix in &prefixes {
                    for key_name in &["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "authorized_keys"] {
                        ssh_paths.push(format!("{}/{}", prefix, key_name));
                    }
                }
            }
            // SSH host keys
            for host_key in &["ssh_host_rsa_key", "ssh_host_ed25519_key", "ssh_host_ecdsa_key"] {
                ssh_paths.push(format!("etc/ssh/{}", host_key));
            }

            for path in &ssh_paths {
                if let Ok(data) = ntfs.read_file(path) {
                    ctx.filesystem_files.insert(path.clone(), data);
                }
            }

            // Linux credential files
            let linux_paths = [
                "etc/shadow",
                "etc/passwd",
                "root/.aws/credentials",
                "root/.git-credentials",
                "root/.netrc",
                "root/.docker/config.json",
                "root/.vnc/passwd",
            ];
            for path in &linux_paths {
                if let Ok(data) = ntfs.read_file(path) {
                    ctx.filesystem_files.insert(path.to_string(), data);
                }
            }

            // Per-user Linux service files
            let user_rel_paths = [
                ".aws/credentials",
                ".git-credentials",
                ".netrc",
                ".docker/config.json",
            ];
            for user in &candidate_users {
                let home = if user == "root" {
                    "root".to_string()
                } else {
                    format!("home/{}", user)
                };
                for rel in &user_rel_paths {
                    let full = format!("{}/{}", home, rel);
                    if let Ok(data) = ntfs.read_file(&full) {
                        ctx.filesystem_files.insert(full, data);
                    }
                }
            }

            // WireGuard configs — try to list etc/wireguard/
            if let Ok(wg_idx) = ntfs.find_file("etc/wireguard") {
                if let Ok(entries) = ntfs.list_directory(wg_idx) {
                    for (name, _is_dir, _idx) in entries {
                        if name.ends_with(".conf") {
                            let path = format!("etc/wireguard/{}", name);
                            if let Ok(data) = ntfs.read_file(&path) {
                                ctx.filesystem_files.insert(path, data);
                            }
                        }
                    }
                }
            }
        }

        Ok(ctx)
    }

    /// Run all compatible credential extractors and emit findings into `collector`.
    pub fn extract(&mut self, collector: &mut Collector) {
        let mut ctx = match self.build_extraction_context() {
            Ok(ctx) => ctx,
            Err(e) => {
                log::warn!("Failed to build extraction context: {}", e);
                return;
            }
        };

        let extractors: Vec<Box<dyn Extractor>> = vec![
            Box::new(SamExtractor),
            Box::new(LsaExtractor),
            Box::new(CachedCredsExtractor),
            Box::new(DpapiExtractor),
            Box::new(BrowserExtractor),
            Box::new(SshExtractor),
            Box::new(LinuxCredsExtractor),
        ];

        for extractor in &extractors {
            if extractor.is_compatible(&ctx) {
                if let Err(e) = extractor.extract(&mut ctx, collector) {
                    log::warn!("{} extractor failed: {}", extractor.name(), e);
                }
            } else {
                log::debug!("{} extractor: prerequisites not met, skipping", extractor.name());
            }
        }
    }

    /// Generates a TargetInfo finding with volume and filesystem details.
    pub fn info(&self) -> Finding {
        let volumes: Vec<VolumeInfo> = self
            .partitions
            .iter()
            .map(|p| VolumeInfo {
                index: p.index,
                partition_type: p.partition_type.clone(),
                offset: p.offset,
                size: p.size,
                label: p.label.clone(),
            })
            .collect();

        let mut filesystems: Vec<FilesystemInfo> = Vec::new();
        if let Some(ntfs) = &self.ntfs {
            filesystems.push(FilesystemInfo {
                fs_type: "NTFS".to_string(),
                label: None,
                total_size: ntfs.volume_size(),
                mount_point: None,
            });
        }

        Finding::TargetInfo(TargetInfoFinding {
            os: self.os.to_string(),
            hostname: self.hostname.clone(),
            version: self.version.clone(),
            architecture: None,
            domain: self.domain.clone(),
            volumes,
            filesystems,
        })
    }
}
