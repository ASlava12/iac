// cargo-fuzz target: feed arbitrary bytes to the manifest document
// parser. Validates that no input shape crashes the YAML
// tokeniser or the typed-Resource deserialiser.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let path = std::path::PathBuf::from("(fuzz)");
    let _ = iac_core::manifest::parse_documents(&path, text);
});
