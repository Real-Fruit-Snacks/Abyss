use abyss_target::extractors::persistence::PersistenceExtractor;
use abyss_target::extractor::Extractor;

#[test]
fn test_persistence_extractor_name() {
    let ext = PersistenceExtractor;
    assert_eq!(ext.name(), "Persistence Mechanism Extractor");
}
