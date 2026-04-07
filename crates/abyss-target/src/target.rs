use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

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
use crate::extractors::{BrowserExtractor, CachedCredsExtractor, CloudExtractor, DpapiExtractor, FirefoxExtractor, LinuxCredsExtractor, LsaExtractor, NtdsExtractor, PersistenceExtractor, SamExtractor, SshExtractor};

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

/// Opened target disk image with OS detection and filesystem discovery.
pub struct Target {
    pub os: OsType,
    pub hostname: Option<String>,
    pub version: Option<String>,
    pub domain: Option<String>,
    pub partitions: Vec<Partition>,
    pub ntfs: Option<NtfsFilesystem>,
    pub extfs: Option<ExtFilesystem>,
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
        let mut ntfs: Option<NtfsFilesystem> = None;
        let mut extfs: Option<ExtFilesystem> = None;

        if partitions.is_empty() {
            let size = shared.size();
            // Try NTFS on whole image
            let mut probe_reader: Box<dyn ReadSeek> =
                Box::new(SliceReader::new(shared.clone_reader(), 0, size));
            if NtfsFilesystem::probe(&mut probe_reader) {
                let open_reader: Box<dyn ReadSeek> =
                    Box::new(SliceReader::new(shared.clone_reader(), 0, size));
                match NtfsFilesystem::open(open_reader) {
                    Ok(fs) => { os = OsType::Windows; ntfs = Some(fs); }
                    Err(e) => log::debug!("NTFS open failed on whole image: {}", e),
                }
            }
            // Try ext if NTFS didn't match
            if ntfs.is_none() {
                let mut probe_reader: Box<dyn ReadSeek> =
                    Box::new(SliceReader::new(shared.clone_reader(), 0, size));
                if ExtFilesystem::probe(&mut probe_reader) {
                    let open_reader: Box<dyn ReadSeek> =
                        Box::new(SliceReader::new(shared.clone_reader(), 0, size));
                    match ExtFilesystem::open(open_reader) {
                        Ok(fs) => { os = OsType::Linux; extfs = Some(fs); }
                        Err(e) => log::debug!("ext open failed on whole image: {}", e),
                    }
                }
            }
        } else {
            // Probe partitions for NTFS
            for partition in &partitions {
                let mut probe_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                    shared.clone_reader(), partition.offset, partition.size,
                ));
                if NtfsFilesystem::probe(&mut probe_reader) {
                    let open_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                        shared.clone_reader(), partition.offset, partition.size,
                    ));
                    match NtfsFilesystem::open(open_reader) {
                        Ok(fs) => { os = OsType::Windows; ntfs = Some(fs); break; }
                        Err(e) => log::debug!("NTFS open failed on partition {}: {}", partition.index, e),
                    }
                }
            }
            // Probe partitions for ext if no NTFS found
            if ntfs.is_none() {
                for partition in &partitions {
                    let mut probe_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                        shared.clone_reader(), partition.offset, partition.size,
                    ));
                    if ExtFilesystem::probe(&mut probe_reader) {
                        let open_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                            shared.clone_reader(), partition.offset, partition.size,
                        ));
                        match ExtFilesystem::open(open_reader) {
                            Ok(fs) => { os = OsType::Linux; extfs = Some(fs); break; }
                            Err(e) => log::debug!("ext open failed on partition {}: {}", partition.index, e),
                        }
                    }
                }
            }
        }

        Ok(Target { os, hostname: None, version: None, domain: None, partitions, ntfs, extfs })
    }

    /// Returns true if any filesystem was successfully opened.
    pub fn has_filesystem(&self) -> bool {
        self.ntfs.is_some() || self.extfs.is_some()
    }

    /// Returns the filesystem type name if one is open.
    pub fn filesystem_type(&self) -> Option<&'static str> {
        if self.ntfs.is_some() {
            Some("NTFS")
        } else if self.extfs.is_some() {
            Some("ext")
        } else {
            None
        }
    }

    /// Read a file by path from whichever filesystem is available.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, TargetError> {
        if let Some(ref mut ntfs) = self.ntfs {
            Ok(ntfs.read_file(path)?)
        } else if let Some(ref mut extfs) = self.extfs {
            Ok(extfs.read_file(path)?)
        } else {
            Err(TargetError::NoFilesystem)
        }
    }

    /// List directory contents from whichever filesystem is available.
    /// Returns Vec of (name, is_directory, id).
    pub fn list_directory_by_path(&mut self, path: &str) -> Result<Vec<(String, bool, u64)>, TargetError> {
        if let Some(ref mut ntfs) = self.ntfs {
            let dir_index = if path == "/" || path.is_empty() {
                5u64 // NTFS root
            } else {
                ntfs.find_file(path)?
            };
            Ok(ntfs.list_directory(dir_index)?)
        } else if let Some(ref mut extfs) = self.extfs {
            let (ino, _inode) = if path == "/" || path.is_empty() {
                let inode = extfs.read_inode(2)?;
                (2u64, inode)
            } else {
                extfs.find_file(path)?
            };
            let entries = extfs.list_directory(ino)?;
            Ok(entries
                .into_iter()
                .filter(|e| e.name != "." && e.name != "..")
                .map(|e| (e.name, e.file_type == abyss_extfs::dir::ExtFileType::Directory, e.inode as u64))
                .collect())
        } else {
            Err(TargetError::NoFilesystem)
        }
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

            // Try to read NTDS.dit (Domain Controller)
            match ntfs.read_file("Windows/NTDS/ntds.dit") {
                Ok(data) => {
                    log::info!("Found NTDS.dit ({} bytes)", data.len());
                    ctx.ntds_dit = Some(data);
                }
                Err(e) => log::debug!("Could not read NTDS.dit: {}", e),
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
                    ctx.filesystem_files.insert(path.to_string(), data);
                }
            }

            // Per-user Linux service files
            let user_rel_paths = [
                ".aws/credentials",
                ".aws/config",
                ".git-credentials",
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
        }

        Ok(ctx)
    }

    /// Build extraction context for Linux targets using extfs.
    fn build_linux_extraction_context(&mut self, mut ctx: ExtractionContext) -> Result<ExtractionContext, TargetError> {
        let extfs = match self.extfs.as_mut() {
            Some(fs) => fs,
            None => return Ok(ctx),
        };

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
                        ctx.filesystem_files.insert(path, data);
                    }
                }
            }
        }

        // SSH host keys
        for host_key in &["ssh_host_rsa_key", "ssh_host_ed25519_key", "ssh_host_ecdsa_key"] {
            let path = format!("etc/ssh/{}", host_key);
            if let Ok(data) = extfs.read_file(&path) {
                ctx.filesystem_files.insert(path, data);
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
                ctx.filesystem_files.insert(path.to_string(), data);
            }
        }

        // Per-user service files
        let user_rel_paths = [
            ".aws/credentials",
            ".aws/config",
            ".git-credentials",
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
        ];
        for user in &candidate_users {
            let home = if user == "root" { "root".to_string() } else { format!("home/{}", user) };
            for rel in &user_rel_paths {
                let full = format!("{}/{}", home, rel);
                if let Ok(data) = extfs.read_file(&full) {
                    ctx.filesystem_files.insert(full, data);
                }
            }
        }

        // WireGuard configs
        if let Ok((_ino, _inode)) = extfs.find_file("etc/wireguard") {
            if let Ok(entries) = extfs.list_directory(_ino) {
                for entry in entries {
                    if entry.name.ends_with(".conf") {
                        let path = format!("etc/wireguard/{}", entry.name);
                        if let Ok(data) = extfs.read_file(&path) {
                            ctx.filesystem_files.insert(path, data);
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
            ("creds", Box::new(FirefoxExtractor)),
            ("creds", Box::new(LinuxCredsExtractor)),
            ("keys",  Box::new(SshExtractor)),
            ("keys",  Box::new(CloudExtractor)),
            ("persist", Box::new(PersistenceExtractor)),
        ];

        for (category, extractor) in &all_extractors {
            if !filter.includes(category) {
                log::debug!("{} extractor: skipped by filter", extractor.name());
                continue;
            }
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
        if let Some(extfs) = &self.extfs {
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
