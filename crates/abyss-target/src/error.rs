use thiserror::Error;

#[derive(Debug, Error)]
pub enum TargetError {
    #[error("could not open target: {detail}")]
    OpenFailed { detail: String },

    #[error("no supported filesystem found")]
    NoFilesystem,

    #[error("OS detection failed")]
    OsDetectionFailed,

    #[error("container error: {0}")]
    Container(#[from] abyss_container::ContainerError),

    #[error("volume error: {0}")]
    Volume(#[from] abyss_volume::VolumeError),

    #[error("ntfs error: {0}")]
    Ntfs(#[from] abyss_ntfs::NtfsError),

    #[error("extfs error: {0}")]
    Extfs(#[from] abyss_extfs::ExtfsError),

    #[error("registry error: {0}")]
    Registry(#[from] abyss_registry::RegistryError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
