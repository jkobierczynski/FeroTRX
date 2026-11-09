//! The control server's example files (`examples/server/`) and the fleet
//! plans (`examples/fleet/`) must keep loading as the formats change.

use std::path::{Path, PathBuf};

use ferotrx_ctl::protocol::Role;
use ferotrx_ctl::{Limits, Token};

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

#[test]
fn server_limits_example_loads() {
    let text = std::fs::read_to_string(examples().join("server/serve.toml")).unwrap();
    let l = Limits::from_toml(&text).unwrap();
    assert_eq!(l.interfaces, ["ftrx-lab"]);
    assert_eq!(l.max_pps, Some(50_000.0));
    assert_eq!(l.max_runs, Some(4));
}

#[test]
fn tokens_example_loads() {
    let tokens = Token::from_file(&examples().join("server/tokens.toml")).unwrap();
    let roles: Vec<_> = tokens.iter().map(|t| (t.name.as_str(), t.role)).collect();
    assert_eq!(
        roles,
        [
            ("alice", Role::Operator),
            ("bob", Role::Operator),
            ("lab-admin", Role::Admin),
            ("dashboard", Role::Read),
        ]
    );
    assert!(tokens[3].matches("test"));
}
