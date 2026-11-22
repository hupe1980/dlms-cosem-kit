//! The object model does not depend on the application layer (D4).
//!
//! `cosem` says what a meter *is*; `xdlms` says how to ask it. The rule is cheap to break
//! by one `use`, and nothing in the type system notices, so it is checked here on the
//! source.

use std::fs;
use std::path::Path;

#[test]
fn cosem_does_not_depend_on_xdlms() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cosem");
    let mut offenders = Vec::new();
    for entry in fs::read_dir(&dir).expect("src/cosem is readable") {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap();
        for (i, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("crate::xdlms") || code.contains("super::super::xdlms") {
                offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
            }
        }
    }
    assert!(offenders.is_empty(), "cosem reaches into xdlms:\n{}", offenders.join("\n"));
}
