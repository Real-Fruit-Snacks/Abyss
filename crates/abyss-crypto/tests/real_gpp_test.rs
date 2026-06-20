//! Integration tests for GPP cpassword decryption using real groups.xml from test-data/.

#[test]
fn test_decrypt_real_gpp_cpassword() {
    let xml = match std::fs::read_to_string("../../test-data/gpp-test/groups.xml") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Skipping: GPP test data not available");
            return;
        }
    };

    // Extract cpassword from XML
    let cpassword_start = xml
        .find("cpassword=\"")
        .expect("cpassword attribute not found in XML")
        + 11;
    let cpassword_end =
        cpassword_start + xml[cpassword_start..].find('"').expect("closing quote not found");
    let cpassword = &xml[cpassword_start..cpassword_end];

    assert!(!cpassword.is_empty(), "cpassword should not be empty");
    eprintln!("Extracted cpassword: {}", cpassword);

    // Decrypt it
    let decrypted = abyss_crypto::decrypt_gpp_password(cpassword)
        .expect("GPP decryption failed");

    // The password from HTB Active box is known: "GPPstillStandingStrong2k18"
    assert_eq!(
        decrypted, "GPPstillStandingStrong2k18",
        "GPP password mismatch: got '{}'",
        decrypted
    );

    eprintln!("Successfully decrypted GPP cpassword: {}", decrypted);
}

#[test]
fn test_parse_real_gpp_xml_extracts_username() {
    let xml = match std::fs::read_to_string("../../test-data/gpp-test/groups.xml") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Skipping: GPP test data not available");
            return;
        }
    };

    assert!(
        xml.contains("userName=\"active.htb\\SVC_TGS\""),
        "Expected userName attribute in GPP XML"
    );
}
