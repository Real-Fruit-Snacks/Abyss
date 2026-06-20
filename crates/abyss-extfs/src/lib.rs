//! abyss-extfs: ext2/ext3/ext4 filesystem parser.

pub mod block_group;
pub mod dir;
pub mod error;
pub mod extent;
pub mod extfs;
pub mod inode;
pub mod superblock;

pub use error::ExtfsError;
pub use extfs::ExtFilesystem;
