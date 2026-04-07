use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

/// Maximum file size to read into memory for extraction (50 MB).
/// Larger files (like NTDS.dit) are handled separately via streaming.
const MAX_FILE_READ_SIZE: u64 = 50 * 1024 * 1024;

use abyss_container::{detect_and_open, SharedBlockDevice};
use abyss_cstruct::read::ReadSeek;
use abyss_extfs::ExtFilesystem;
use abyss_ntfs::NtfsFilesystem;
use abyss_output::collector::Collector;
use abyss_output::finding::{FilesystemInfo, Finding, TargetInfoFinding, VolumeInfo};
use abyss_volume::{discover_partitions, Partition};

use crate::detect::OsType;
use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};
use crate::extractors::{BrowserExtractor, CachedCredsExtractor, CertExtractor, CloudExtractor, CredMgrExtractor, DpapiExtractor, FirefoxExtractor, GppExtractor, LinuxCredsExtractor, LsaExtractor, NtdsExtractor, PersistenceExtractor, SamExtractor, SshExtractor};

/// Reader that presents a slice of a SharedBlockDevice as a standalone ReadSeek.
struct SliceReader {
    device: SharedBlockDevice,
    base_offset: u64,
    size: u64,
    position: u64,
}

impl SliceReader {
    fn new(device: SharedBlockDevice, base_offset: u64, size: u64) -> Self {
        Self { device, base_offset, size, position: 0 }
    }
}

impl Read for SliceReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.size.saturating_sub(self.position);
        if remaining == 0 { return Ok(0); }
        let max = buf.len().min(remaining as usize);
        self.device.seek(SeekFrom::Start(self.base_offset + self.position))?;
        let n = self.device.read(&mut buf[..max])?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for SliceReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => (self.size as i64 + offset).max(0) as u64,
            SeekFrom::Current(offset) => (self.position as i64 + offset).max(0) as u64,
        };
        self.position = new_pos.min(self.size);
        Ok(self.position)
    }
}

/// Controls which categories of extractors to run.
#[derive(Debug, Clone)]
pub enum ExtractFilter {
    /// Run all extractors.
    All,
    /// Run only the specified categories ("creds", "keys", "persist").
    Categories(Vec<String>),
}

impl ExtractFilter {
    /// Build a filter from CLI flags.
    pub fn from_flags(creds: bool, keys: bool, persist: bool, all: bool) -> Self {
        if all || (!creds && !keys && !persist) {
            return ExtractFilter::All;
        }
        let mut cats = Vec::new();
        if creds { cats.push("creds".to_string()); }
        if keys { cats.push("keys".to_string()); }
        if persist { cats.push("persist".to_string()); }
        ExtractFilter::Categories(cats)
    }

    /// Returns true if the given category should run.
    pub fn includes(&self, category: &str) -> bool {
        match self {
            ExtractFilter::All => true,
            ExtractFilter::Categories(cats) => cats.iter().any(|c| c == category),
        }
    }
}

/// Recursively scan an NTFS directory for XML files and add them to the map.
/// Best-effort: silently skips unreadable entries.
fn scan_sysvol_for_gpp_xml(
    ntfs: &mut abyss_ntfs::NtfsFilesystem,
    dir_path: &str,
    files: &mut std::collections::HashMap<String, Vec<u8>>,
) {
    let dir_idx = match ntfs.find_file(dir_path) {
        Ok(idx) => idx,
        Err(_) => return,
    };
    let entries = match ntfs.list_directory(dir_idx) {
        Ok(e) => e,
        Err(_) => return,
    };
    for (name, is_dir, _idx) in entries {
        if name == "." || name == ".." || name.is_empty() {
            continue;
        }
        let child_path = format!("{}/{}", dir_path, name);
        if is_dir {
            scan_sysvol_for_gpp_xml(ntfs, &child_path, files);
        } else if name.to_lowercase().ends_with(".xml") {
            if files.contains_key(&child_path) {
                continue;
            }
            if let Ok(data) = ntfs.read_file(&child_path) {
                if data.len() <= 50 * 1024 * 1024 {
                    files.insert(child_path, data);
                }
            }
        }
    }
}

/// Opened target disk image with OS detection and filesystem discovery.
pub struct Target {
    pub os: OsType,
    pub hostname: Option<String>,
    pub version: Option<String>,
    pub domain: Option<String>,
    pub partitions: Vec<Partition>,
    pub ntfs_filesystems: Vec<NtfsFilesystem>,
    pub extfs_filesystems: Vec<ExtFilesystem>,
}

impl Target {
    /// Open a disk image at `path`, discover partitions, and probe filesystems.
    pub fn open(path: &Path) -> Result<Self, TargetError> {
        let file = File::open(path).map_err(|e| TargetError::OpenFailed {
            detail: e.to_string(),
        })?;
        let reader: Box<dyn ReadSeek> = Box::new(BufReader::new(file));
        let container = detect_and_open(reader)?;
        let shared = SharedBlockDevice::new(container);

        // Partition discovery using the virtual disk surface
        let mut disc_reader = shared.clone_reader();
        let partitions = match discover_partitions(&mut disc_reader, 512u64) {
            Ok(parts) => parts,
            Err(_) => Vec::new(),
        };

        let mut os = OsType::Unknown;
        let mut ntfs_filesystems: Vec<NtfsFilesystem> = Vec::new();
        let mut extfs_filesystems: Vec<ExtFilesystem> = Vec::new();

        if partitions.is_empty() {
            let size = shared.size();
            // Try NTFS on whole image
            let mut probe_reader: Box<dyn ReadSeek> =
                Box::new(SliceReader::new(shared.clone_reader(), 0, size));
            if NtfsFilesystem::probe(&mut probe_reader) {
                let open_reader: Box<dyn ReadSeek> =
                    Box::new(SliceReader::new(shared.clone_reader(), 0, size));
                match NtfsFilesystem::open(open_reader) {
                    Ok(fs) => {
                        if os == OsType::Unknown { os = OsType::Windows; }
                        ntfs_filesystems.push(fs);
                    }
                    Err(e) => log::warn!("NTFS open failed on whole image: {}", e),
                }
            }
            // Try ext on whole image (independent of NTFS result)
            let mut probe_reader: Box<dyn ReadSeek> =
                Box::new(SliceReader::new(shared.clone_reader(), 0, size));
            if ExtFilesystem::probe(&mut probe_reader) {
                let open_reader: Box<dyn ReadSeek> =
                    Box::new(SliceReader::new(shared.clone_reader(), 0, size));
                match ExtFilesystem::open(open_reader) {
                    Ok(fs) => {
                        if os == OsType::Unknown { os = OsType::Linux; }
                        extfs_filesystems.push(fs);
                    }
                    Err(e) => log::warn!("ext open failed on whole image: {}", e),
                }
            }
        } else {
            // Probe each partition for both NTFS and ext; collect all matches
            for partition in &partitions {
                let mut probe_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                    shared.clone_reader(), partition.offset, partition.size,
                ));
                if NtfsFilesystem::probe(&mut probe_reader) {
                    let open_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                        shared.clone_reader(), partition.offset, partition.size,
                    ));
                    match NtfsFilesystem::open(open_reader) {
                        Ok(fs) => {
                            if os == OsType::Unknown { os = OsType::Windows; }
                            ntfs_filesystems.push(fs);
                        }
                        Err(e) => log::warn!("NTFS open failed on partition {}: {}", partition.index, e),
                    }
                } else {
                    let mut probe_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                        shared.clone_reader(), partition.offset, partition.size,
                    ));
                    if ExtFilesystem::probe(&mut probe_reader) {
                        let open_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                            shared.clone_reader(), partition.offset, partition.size,
                        ));
                        match ExtFilesystem::open(open_reader) {
                            Ok(fs) => {
                                if os == OsType::Unknown { os = OsType::Linux; }
                                extfs_filesystems.push(fs);
                            }
                            Err(e) => log::warn!("ext open failed on partition {}: {}", partition.index, e),
                        }
                    }
                }
            }
        }

        // If both NTFS and ext filesystems found (dual-boot), keep the OS that has more
        if !ntfs_filesystems.is_empty() && !extfs_filesystems.is_empty() {
            if extfs_filesystems.len() > ntfs_filesystems.len() {
                os = OsType::Linux;
            } else {
                os = OsType::Windows;
            }
        }

        Ok(Target { os, hostname: None, version: None, domain: None, partitions, ntfs_filesystems, extfs_filesystems })
    }

    /// Returns true if any filesystem was successfully opened.
    pub fn has_filesystem(&self) -> bool {
        !self.ntfs_filesystems.is_empty() || !self.extfs_filesystems.is_empty()
    }

    /// Returns the filesystem type name if one is open.
    pub fn filesystem_type(&self) -> Option<&'static str> {
        if !self.ntfs_filesystems.is_empty() && !self.extfs_filesystems.is_empty() {
            Some("NTFS+ext")
        } else if !self.ntfs_filesystems.is_empty() {
            Some("NTFS")
        } else if !self.extfs_filesystems.is_empty() {
            Some("ext")
        } else {
            None
        }
    }

    /// Read a file by path from whichever filesystem is available.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, TargetError> {
        for ntfs in &mut self.ntfs_filesystems {
            if let Ok(data) = ntfs.read_file(path) {
                return Ok(data);
            }
        }
        for extfs in &mut self.extfs_filesystems {
            if let Ok(data) = extfs.read_file(path) {
                return Ok(data);
            }
        }
        Err(TargetError::NoFilesystem)
    }

    /// Read a file, but skip if larger than MAX_FILE_READ_SIZE.
    /// Returns None if the file is too large or doesn't exist.
    #[allow(dead_code)]
    fn read_file_capped(&mut self, path: &str) -> Option<Vec<u8>> {
        match self.read_file(path) {
            Ok(data) => {
                if data.len() as u64 > MAX_FILE_READ_SIZE {
                    log::debug!("Skipping large file {} ({} bytes)", path, data.len());
                    None
                } else {
                    Some(data)
                }
            }
            Err(_) => None,
        }
    }

    /// List directory contents from whichever filesystem is available.
    /// Returns Vec of (name, is_directory, id).
    pub fn list_directory_by_path(&mut self, path: &str) -> Result<Vec<(String, bool, u64)>, TargetError> {
        // Try each NTFS filesystem first
        for ntfs in &mut self.ntfs_filesystems {
            let dir_index = if path == "/" || path.is_empty() {
                5u64 // NTFS root
            } else {
                match ntfs.find_file(path) {
                    Ok(idx) => idx,
                    Err(_) => continue,
                }
            };
            if let Ok(entries) = ntfs.list_directory(dir_index) {
                return Ok(entries);
            }
        }
        // Try each ext filesystem
        for extfs in &mut self.extfs_filesystems {
            let ino = if path == "/" || path.is_empty() {
                2u64
            } else {
                match extfs.find_file(path) {
                    Ok((ino, _)) => ino,
                    Err(_) => continue,
                }
            };
            if let Ok(entries) = extfs.list_directory(ino) {
                return Ok(entries
                    .into_iter()
                    .filter(|e| e.name != "." && e.name != "..")
                    .map(|e| (e.name, e.file_type == abyss_extfs::dir::ExtFileType::Directory, e.inode as u64))
                    .collect());
            }
        }
        Err(TargetError::NoFilesystem)
    }

    /// Build the extraction context by loading registry hives and credential files.
    fn build_extraction_context(&mut self) -> Result<ExtractionContext, TargetError> {
        let mut ctx = ExtractionContext::new();

        // Build Linux extraction context from extfs
        if self.os == OsType::Linux {
            return self.build_linux_extraction_context(ctx);
        }

        if self.os != OsType::Windows {
            return Ok(ctx);
        }

        let hive_paths = [
            ("SYSTEM", "Windows/System32/config/SYSTEM"),
            ("SAM", "Windows/System32/config/SAM"),
            ("SECURITY", "Windows/System32/config/SECURITY"),
        ];

        for ntfs in &mut self.ntfs_filesystems {
            for (name, path) in &hive_paths {
                match ntfs.read_file(path) {
                    Ok(data) => {
                        let cursor = std::io::Cursor::new(data);
                        match abyss_registry::RegistryHive::open(Box::new(cursor)) {
                            Ok(hive) => {
                                log::info!("Opened {} hive from {}", name, path);
                                match *name {
                                    "SYSTEM" => { if ctx.system_hive.is_none() { ctx.system_hive = Some(hive); } }
                                    "SAM" => { if ctx.sam_hive.is_none() { ctx.sam_hive = Some(hive); } }
                                    "SECURITY" => { if ctx.security_hive.is_none() { ctx.security_hive = Some(hive); } }
                                    _ => {}
                                }
                            }
                            Err(e) => log::warn!("Failed to parse {} hive: {}", name, e),
                        }
                    }
                    Err(e) => log::debug!("Could not read {}: {}", path, e),
                }
            }

            // Try to read NTDS.dit (Domain Controller) — not size-capped, ESE parser needs full file
            if ctx.ntds_dit.is_none() {
                match ntfs.read_file("Windows/NTDS/ntds.dit") {
                    Ok(data) => {
                        log::info!("Read NTDS.dit: {} bytes ({:.1} MB)", data.len(), data.len() as f64 / 1_048_576.0);
                        ctx.ntds_dit = Some(data);
                    }
                    Err(e) => log::debug!("NTDS.dit not found: {}", e),
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
                            && !ctx.discovered_users.contains(&name)
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
                    if data.len() <= MAX_FILE_READ_SIZE as usize {
                        ctx.filesystem_files.entry(path.clone()).or_insert(data);
                    } else {
                        log::debug!("Skipping large file {} ({} bytes)", path, data.len());
                    }
                }
            }

            // Linux credential files
            let linux_paths = [
                "etc/shadow",
                "etc/passwd",
                "root/.aws/credentials",
                "root/.aws/config",
                "root/.git-credentials",
                "root/.netrc",
                "root/.docker/config.json",
                "root/.vnc/passwd",
                "root/.azure/accessTokens.json",
                "root/.azure/azureProfile.json",
                "root/.azure/msal_token_cache.json",
                "root/.config/gcloud/application_default_credentials.json",
                "root/.config/gcloud/properties",
                "root/.config/gh/hosts.yml",
                "root/.config/hub",
                "root/.kube/config",
                "root/.terraform.d/credentials.tfrc.json",
                "root/.env",
                "root/.bashrc",
                "root/.bash_profile",
                "root/.profile",
                "root/.zshrc",
            ];
            for path in &linux_paths {
                if let Ok(data) = ntfs.read_file(path) {
                    if data.len() <= MAX_FILE_READ_SIZE as usize {
                        ctx.filesystem_files.entry(path.to_string()).or_insert(data);
                    } else {
                        log::debug!("Skipping large file {} ({} bytes)", path, data.len());
                    }
                }
            }

            // Per-user Linux service files
            let user_rel_paths = [
                ".aws/credentials",
                ".aws/config",
                ".git-credentials",
                ".config/git/credentials",
                ".config/netlify/config.json",
                ".npmrc",
                ".pypirc",
                ".netrc",
                ".docker/config.json",
                ".azure/accessTokens.json",
                ".azure/azureProfile.json",
                ".azure/msal_token_cache.json",
                ".config/gcloud/application_default_credentials.json",
                ".config/gcloud/properties",
                ".config/gh/hosts.yml",
                ".config/hub",
                ".kube/config",
                ".terraform.d/credentials.tfrc.json",
                ".env",
                ".bashrc",
                ".bash_profile",
                ".profile",
                ".zshrc",
                ".gitconfig",
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
                        if data.len() <= MAX_FILE_READ_SIZE as usize {
                            ctx.filesystem_files.entry(full).or_insert(data);
                        } else {
                            log::debug!("Skipping large file {} ({} bytes)", full, data.len());
                        }
                    }
                }
            }

            // Kubernetes service account token
            if let Ok(data) = ntfs.read_file("var/run/secrets/kubernetes.io/serviceaccount/token") {
                if data.len() <= MAX_FILE_READ_SIZE as usize {
                    ctx.filesystem_files.entry("var/run/secrets/kubernetes.io/serviceaccount/token".to_string()).or_insert(data);
                }
            }

            // Windows-specific cloud config paths
            let win_cloud_rel_paths = [
                ".aws/credentials",
                ".aws/config",
                ".azure/accessTokens.json",
                ".azure/azureProfile.json",
                ".azure/msal_token_cache.json",
                "AppData/Roaming/gcloud/application_default_credentials.json",
                "AppData/Roaming/gcloud/properties",
                ".config/gh/hosts.yml",
                ".docker/config.json",
                ".kube/config",
                ".terraform.d/credentials.tfrc.json",
            ];
            for user in &candidate_users {
                for rel in &win_cloud_rel_paths {
                    let full = format!("Users/{}/{}", user, rel);
                    if let Ok(data) = ntfs.read_file(&full) {
                        if data.len() <= MAX_FILE_READ_SIZE as usize {
                            ctx.filesystem_files.entry(full).or_insert(data);
                        } else {
                            log::debug!("Skipping large file {} ({} bytes)", full, data.len());
                        }
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
                                if data.len() <= MAX_FILE_READ_SIZE as usize {
                                    ctx.filesystem_files.entry(path).or_insert(data);
                                } else {
                                    log::debug!("Skipping large file {} ({} bytes)", path, data.len());
                                }
                            }
                        }
                    }
                }
            }

            // Firefox profile discovery (Windows)
            for user in &candidate_users {
                let profiles_dir = format!(
                    "Users/{}/AppData/Roaming/Mozilla/Firefox/Profiles",
                    user
                );
                if let Ok(profiles_idx) = ntfs.find_file(&profiles_dir) {
                    if let Ok(entries) = ntfs.list_directory(profiles_idx) {
                        for (profile_name, is_dir, _idx) in entries {
                            if !is_dir
                                || profile_name == "."
                                || profile_name == ".."
                            {
                                continue;
                            }
                            let key4_path = format!(
                                "{}/{}/key4.db",
                                profiles_dir, profile_name
                            );
                            let logins_path = format!(
                                "{}/{}/logins.json",
                                profiles_dir, profile_name
                            );
                            let key4 = ntfs.read_file(&key4_path);
                            let logins = ntfs.read_file(&logins_path);
                            if let (Ok(key4_data), Ok(logins_data)) =
                                (key4, logins)
                            {
                                log::info!(
                                    "Found Firefox profile for {}: {}",
                                    user,
                                    profile_name
                                );
                                ctx.firefox_profiles.push((
                                    user.clone(),
                                    key4_data,
                                    logins_data,
                                ));
                            }
                        }
                    }
                }
            }

            // Firefox profile discovery (Linux paths on NTFS)
            for user in &candidate_users {
                let home = if user == "root" {
                    "root".to_string()
                } else {
                    format!("home/{}", user)
                };
                let profiles_dir =
                    format!("{}/.mozilla/firefox", home);
                if let Ok(profiles_idx) = ntfs.find_file(&profiles_dir) {
                    if let Ok(entries) = ntfs.list_directory(profiles_idx) {
                        for (profile_name, is_dir, _idx) in entries {
                            if !is_dir
                                || profile_name == "."
                                || profile_name == ".."
                            {
                                continue;
                            }
                            let key4_path = format!(
                                "{}/{}/key4.db",
                                profiles_dir, profile_name
                            );
                            let logins_path = format!(
                                "{}/{}/logins.json",
                                profiles_dir, profile_name
                            );
                            let key4 = ntfs.read_file(&key4_path);
                            let logins = ntfs.read_file(&logins_path);
                            if let (Ok(key4_data), Ok(logins_data)) =
                                (key4, logins)
                            {
                                log::info!(
                                    "Found Firefox profile for {}: {}",
                                    user,
                                    profile_name
                                );
                                ctx.firefox_profiles.push((
                                    user.clone(),
                                    key4_data,
                                    logins_data,
                                ));
                            }
                        }
                    }
                }
            }

            // Scan DPAPI master key files: Users/<user>/AppData/Roaming/Microsoft/Protect/<SID>/<GUID>
            for user in &candidate_users {
                let protect_dir = format!(
                    "Users/{}/AppData/Roaming/Microsoft/Protect",
                    user
                );
                let sid_entries = match ntfs.find_file(&protect_dir) {
                    Ok(idx) => ntfs.list_directory(idx).unwrap_or_default(),
                    Err(_) => continue,
                };
                for (sid_name, is_dir, _idx) in &sid_entries {
                    if !is_dir || sid_name == "." || sid_name == ".." || !sid_name.starts_with("S-") {
                        continue;
                    }
                    let sid_dir = format!("{}/{}", protect_dir, sid_name);
                    let guid_entries = match ntfs.find_file(&sid_dir) {
                        Ok(idx) => ntfs.list_directory(idx).unwrap_or_default(),
                        Err(_) => continue,
                    };
                    for (guid_name, is_file_dir, _) in &guid_entries {
                        if *is_file_dir || guid_name == "." || guid_name == ".." || guid_name == "Preferred" {
                            continue;
                        }
                        // GUID filenames are like "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        if guid_name.len() < 32 {
                            continue;
                        }
                        let mk_path = format!("{}/{}", sid_dir, guid_name);
                        match ntfs.read_file(&mk_path) {
                            Ok(data) => {
                                if data.len() <= MAX_FILE_READ_SIZE as usize {
                                    log::info!(
                                        "Found DPAPI master key file: {} ({} bytes)",
                                        mk_path,
                                        data.len()
                                    );
                                    ctx.dpapi_master_key_files.push((
                                        sid_name.clone(),
                                        guid_name.clone(),
                                        data,
                                    ));
                                }
                            }
                            Err(e) => {
                                log::debug!("Could not read master key file {}: {}", mk_path, e);
                            }
                        }
                    }
                }
            }

            // Also scan SYSTEM profile for machine-level master keys
            let system_protect_paths = [
                "Windows/System32/Microsoft/Protect/S-1-5-18/User",
                "Windows/System32/Microsoft/Protect/S-1-5-18",
            ];
            for protect_dir in &system_protect_paths {
                let entries = match ntfs.find_file(protect_dir) {
                    Ok(idx) => ntfs.list_directory(idx).unwrap_or_default(),
                    Err(_) => continue,
                };
                for (name, is_dir, _) in &entries {
                    if *is_dir || name == "." || name == ".." || name == "Preferred" {
                        continue;
                    }
                    if name.len() < 32 {
                        continue;
                    }
                    let mk_path = format!("{}/{}", protect_dir, name);
                    match ntfs.read_file(&mk_path) {
                        Ok(data) => {
                            if data.len() <= MAX_FILE_READ_SIZE as usize {
                                log::info!(
                                    "Found SYSTEM DPAPI master key file: {} ({} bytes)",
                                    mk_path,
                                    data.len()
                                );
                                ctx.dpapi_master_key_files.push((
                                    "S-1-5-18".to_string(),
                                    name.clone(),
                                    data,
                                ));
                            }
                        }
                        Err(e) => {
                            log::debug!("Could not read system master key file {}: {}", mk_path, e);
                        }
                    }
                }
            }

            // Scan Credential Manager files: Users/<user>/AppData/Local/Microsoft/Credentials/<GUID>
            for user in &candidate_users {
                let cred_dir = format!("Users/{}/AppData/Local/Microsoft/Credentials", user);
                if let Ok(idx) = ntfs.find_file(&cred_dir) {
                    if let Ok(entries) = ntfs.list_directory(idx) {
                        for (name, is_dir, _) in entries {
                            if !is_dir && name != "." && name != ".." {
                                let path = format!("{}/{}", cred_dir, name);
                                if let Ok(data) = ntfs.read_file(&path) {
                                    if data.len() <= MAX_FILE_READ_SIZE as usize {
                                        log::info!(
                                            "Found Credential Manager file: {} ({} bytes)",
                                            path,
                                            data.len()
                                        );
                                        ctx.filesystem_files.entry(path).or_insert(data);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Scan for certificates in Windows certificate store
            for user in &candidate_users {
                let cert_dir = format!(
                    "Users/{}/AppData/Roaming/Microsoft/SystemCertificates/My/Certificates",
                    user
                );
                if let Ok(idx) = ntfs.find_file(&cert_dir) {
                    if let Ok(entries) = ntfs.list_directory(idx) {
                        for (name, is_dir, _) in entries {
                            if !is_dir && name != "." && name != ".." {
                                let path = format!("{}/{}", cert_dir, name);
                                if let Ok(data) = ntfs.read_file(&path) {
                                    if data.len() <= MAX_FILE_READ_SIZE as usize {
                                        log::info!(
                                            "Found certificate: {} ({} bytes)",
                                            path,
                                            data.len()
                                        );
                                        ctx.filesystem_files.entry(path).or_insert(data);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Scan for private key containers (DPAPI-encrypted RSA keys)
            for user in &candidate_users {
                let crypto_dir = format!(
                    "Users/{}/AppData/Roaming/Microsoft/Crypto/RSA",
                    user
                );
                if let Ok(idx) = ntfs.find_file(&crypto_dir) {
                    if let Ok(sid_entries) = ntfs.list_directory(idx) {
                        for (sid_name, is_dir, _) in sid_entries {
                            if !is_dir || sid_name == "." || sid_name == ".." {
                                continue;
                            }
                            let sid_dir = format!("{}/{}", crypto_dir, sid_name);
                            if let Ok(sid_idx) = ntfs.find_file(&sid_dir) {
                                if let Ok(key_entries) = ntfs.list_directory(sid_idx) {
                                    for (key_name, key_is_dir, _) in key_entries {
                                        if key_is_dir || key_name == "." || key_name == ".." {
                                            continue;
                                        }
                                        let path = format!("{}/{}", sid_dir, key_name);
                                        if let Ok(data) = ntfs.read_file(&path) {
                                            if data.len() <= MAX_FILE_READ_SIZE as usize {
                                                log::info!(
                                                    "Found private key container: {} ({} bytes)",
                                                    path,
                                                    data.len()
                                                );
                                                ctx.filesystem_files.entry(path).or_insert(data);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Scan machine-level private key containers
            let machine_keys_dir = "ProgramData/Microsoft/Crypto/RSA/MachineKeys";
            if let Ok(idx) = ntfs.find_file(machine_keys_dir) {
                if let Ok(entries) = ntfs.list_directory(idx) {
                    for (name, is_dir, _) in entries {
                        if !is_dir && name != "." && name != ".." {
                            let path = format!("{}/{}", machine_keys_dir, name);
                            if let Ok(data) = ntfs.read_file(&path) {
                                if data.len() <= MAX_FILE_READ_SIZE as usize {
                                    log::info!(
                                        "Found machine private key: {} ({} bytes)",
                                        path,
                                        data.len()
                                    );
                                    ctx.filesystem_files.entry(path).or_insert(data);
                                }
                            }
                        }
                    }
                }
            }

            // Scan SYSVOL for GPP XML files containing cpassword
            let sysvol_roots = [
                "Windows/SYSVOL/domain/Policies",
                "Windows/SYSVOL/sysvol",
                "SYSVOL",
            ];
            for sysvol_root in &sysvol_roots {
                scan_sysvol_for_gpp_xml(ntfs, sysvol_root, &mut ctx.filesystem_files);
            }
        }

        Ok(ctx)
    }

    /// Build extraction context for Linux targets using extfs.
    fn build_linux_extraction_context(&mut self, mut ctx: ExtractionContext) -> Result<ExtractionContext, TargetError> {
        for extfs in &mut self.extfs_filesystems {
            // Discover users from home/ directory
            if let Ok(entries) = extfs.list_directory(2) {
                // Look for "home" in root
                for entry in &entries {
                    if entry.name == "home" && entry.file_type == abyss_extfs::dir::ExtFileType::Directory {
                        if let Ok(home_entries) = extfs.list_directory(entry.inode as u64) {
                            for he in home_entries {
                                if !he.name.is_empty() && he.name != "." && he.name != ".." && he.file_type == abyss_extfs::dir::ExtFileType::Directory {
                                    if !ctx.discovered_users.contains(&he.name) {
                                        ctx.discovered_users.push(he.name);
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }

            let candidate_users: Vec<String> = {
                let mut v = ctx.discovered_users.clone();
                for common in &["root", "ubuntu", "ec2-user", "admin", "user"] {
                    let s = common.to_string();
                    if !v.contains(&s) {
                        v.push(s);
                    }
                }
                v
            };

            // SSH keys
            for user in &candidate_users {
                let prefixes: Vec<String> = if user == "root" {
                    vec!["root/.ssh".to_string(), "home/root/.ssh".to_string()]
                } else {
                    vec![format!("home/{}/.ssh", user)]
                };
                for prefix in &prefixes {
                    for key_name in &["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "authorized_keys"] {
                        let path = format!("{}/{}", prefix, key_name);
                        if let Ok(data) = extfs.read_file(&path) {
                            if data.len() <= MAX_FILE_READ_SIZE as usize {
                                ctx.filesystem_files.entry(path).or_insert(data);
                            } else {
                                log::debug!("Skipping large file {} ({} bytes)", path, data.len());
                            }
                        }
                    }
                }
            }

            // SSH host keys
            for host_key in &["ssh_host_rsa_key", "ssh_host_ed25519_key", "ssh_host_ecdsa_key"] {
                let path = format!("etc/ssh/{}", host_key);
                if let Ok(data) = extfs.read_file(&path) {
                    if data.len() <= MAX_FILE_READ_SIZE as usize {
                        ctx.filesystem_files.entry(path).or_insert(data);
                    } else {
                        log::debug!("Skipping large file {} ({} bytes)", path, data.len());
                    }
                }
            }

            // Linux credential files
            let linux_paths = [
                "etc/shadow", "etc/passwd",
                "root/.aws/credentials", "root/.aws/config",
                "root/.git-credentials",
                "root/.netrc", "root/.docker/config.json", "root/.vnc/passwd",
                "root/.azure/accessTokens.json",
                "root/.azure/azureProfile.json",
                "root/.azure/msal_token_cache.json",
                "root/.config/gcloud/application_default_credentials.json",
                "root/.config/gcloud/properties",
                "root/.config/gh/hosts.yml",
                "root/.config/hub",
                "root/.kube/config",
                "root/.terraform.d/credentials.tfrc.json",
                "root/.env",
                "root/.bashrc",
                "root/.bash_profile",
                "root/.profile",
                "root/.zshrc",
            ];
            for path in &linux_paths {
                if let Ok(data) = extfs.read_file(path) {
                    if data.len() <= MAX_FILE_READ_SIZE as usize {
                        ctx.filesystem_files.entry(path.to_string()).or_insert(data);
                    } else {
                        log::debug!("Skipping large file {} ({} bytes)", path, data.len());
                    }
                }
            }

            // Per-user service files
            let user_rel_paths = [
                ".aws/credentials",
                ".aws/config",
                ".git-credentials",
                ".config/git/credentials",
                ".config/netlify/config.json",
                ".npmrc",
                ".pypirc",
                ".netrc",
                ".docker/config.json",
                ".azure/accessTokens.json",
                ".azure/azureProfile.json",
                ".azure/msal_token_cache.json",
                ".config/gcloud/application_default_credentials.json",
                ".config/gcloud/properties",
                ".config/gh/hosts.yml",
                ".config/hub",
                ".kube/config",
                ".terraform.d/credentials.tfrc.json",
                ".env",
                ".bashrc",
                ".bash_profile",
                ".profile",
                ".zshrc",
                ".gitconfig",
            ];
            for user in &candidate_users {
                let home = if user == "root" { "root".to_string() } else { format!("home/{}", user) };
                for rel in &user_rel_paths {
                    let full = format!("{}/{}", home, rel);
                    if let Ok(data) = extfs.read_file(&full) {
                        if data.len() <= MAX_FILE_READ_SIZE as usize {
                            ctx.filesystem_files.entry(full).or_insert(data);
                        } else {
                            log::debug!("Skipping large file {} ({} bytes)", full, data.len());
                        }
                    }
                }
            }

            // Kubernetes service account token
            if let Ok(data) = extfs.read_file("var/run/secrets/kubernetes.io/serviceaccount/token") {
                if data.len() <= MAX_FILE_READ_SIZE as usize {
                    ctx.filesystem_files.entry("var/run/secrets/kubernetes.io/serviceaccount/token".to_string()).or_insert(data);
                } else {
                    log::debug!("Skipping large file var/run/secrets/kubernetes.io/serviceaccount/token ({} bytes)", data.len());
                }
            }

            // WireGuard configs
            if let Ok((_ino, _inode)) = extfs.find_file("etc/wireguard") {
                if let Ok(entries) = extfs.list_directory(_ino) {
                    for entry in entries {
                        if entry.name.ends_with(".conf") {
                            let path = format!("etc/wireguard/{}", entry.name);
                            if let Ok(data) = extfs.read_file(&path) {
                                if data.len() <= MAX_FILE_READ_SIZE as usize {
                                    ctx.filesystem_files.entry(path).or_insert(data);
                                } else {
                                    log::debug!("Skipping large file {} ({} bytes)", path, data.len());
                                }
                            }
                        }
                    }
                }
            }

            // Firefox profile discovery (Linux)
            for user in &candidate_users {
                let home = if user == "root" {
                    "root".to_string()
                } else {
                    format!("home/{}", user)
                };
                let profiles_dir = format!("{}/.mozilla/firefox", home);
                if let Ok((profiles_ino, _)) = extfs.find_file(&profiles_dir) {
                    if let Ok(entries) = extfs.list_directory(profiles_ino) {
                        for entry in entries {
                            if entry.file_type != abyss_extfs::dir::ExtFileType::Directory
                                || entry.name == "."
                                || entry.name == ".."
                            {
                                continue;
                            }
                            let key4_path =
                                format!("{}/{}/key4.db", profiles_dir, entry.name);
                            let logins_path =
                                format!("{}/{}/logins.json", profiles_dir, entry.name);
                            let key4 = extfs.read_file(&key4_path);
                            let logins = extfs.read_file(&logins_path);
                            if let (Ok(key4_data), Ok(logins_data)) = (key4, logins) {
                                log::info!(
                                    "Found Firefox profile for {}: {}",
                                    user,
                                    entry.name
                                );
                                ctx.firefox_profiles.push((
                                    user.clone(),
                                    key4_data,
                                    logins_data,
                                ));
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
        self.extract_filtered(collector, &ExtractFilter::All);
    }

    /// Run extractors filtered by category.
    pub fn extract_filtered(&mut self, collector: &mut Collector, filter: &ExtractFilter) {
        let mut ctx = match self.build_extraction_context() {
            Ok(ctx) => ctx,
            Err(e) => {
                log::warn!("Failed to build extraction context: {}", e);
                return;
            }
        };

        let all_extractors: Vec<(&str, Box<dyn Extractor>)> = vec![
            ("creds", Box::new(SamExtractor)),
            ("creds", Box::new(NtdsExtractor)),
            ("creds", Box::new(LsaExtractor)),
            ("creds", Box::new(CachedCredsExtractor)),
            ("creds", Box::new(DpapiExtractor)),
            ("creds", Box::new(BrowserExtractor)),
            ("creds", Box::new(CredMgrExtractor)),
            ("creds", Box::new(FirefoxExtractor)),
            ("creds", Box::new(LinuxCredsExtractor)),
            ("creds", Box::new(GppExtractor)),
            ("keys",  Box::new(SshExtractor)),
            ("keys",  Box::new(CloudExtractor)),
            ("keys",  Box::new(CertExtractor)),
            ("persist", Box::new(PersistenceExtractor)),
        ];

        for (category, extractor) in &all_extractors {
            if !filter.includes(category) {
                log::debug!("{} extractor: skipped by filter", extractor.name());
                continue;
            }
            if !extractor.is_compatible(&ctx) {
                log::debug!("{} extractor: prerequisites not met, skipping", extractor.name());
                continue;
            }
            let name = extractor.name();
            // Safety: we use AssertUnwindSafe because extractors may not be
            // UnwindSafe, but we accept that risk to keep the pipeline alive.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                extractor.extract(&mut ctx, collector)
            }));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => log::warn!("{} extractor failed: {}", name, e),
                Err(_) => log::error!("{} extractor panicked! Continuing with remaining extractors.", name),
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
        for ntfs in &self.ntfs_filesystems {
            filesystems.push(FilesystemInfo {
                fs_type: "NTFS".to_string(),
                label: None,
                total_size: ntfs.volume_size(),
                mount_point: None,
            });
        }
        for extfs in &self.extfs_filesystems {
            filesystems.push(FilesystemInfo {
                fs_type: "ext".to_string(),
                label: None,
                total_size: extfs.volume_size(),
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
