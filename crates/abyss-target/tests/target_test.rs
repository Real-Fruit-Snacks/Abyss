use abyss_target::detect::OsType;

#[test]
fn os_type_display_windows() {
    assert_eq!(OsType::Windows.to_string(), "Windows");
}

#[test]
fn os_type_display_linux() {
    assert_eq!(OsType::Linux.to_string(), "Linux");
}

#[test]
fn os_type_display_unknown() {
    assert_eq!(OsType::Unknown.to_string(), "Unknown");
}
