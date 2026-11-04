//! `ferotrx check`: profile and scenario files checked without sending.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;
use ferotrx_core::check::{check_file, FileKind};

#[derive(Args)]
pub struct CheckArgs {
    /// Traffic, TCP, UDP or benchmark profiles, or scenarios.
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// The kind of the files, when guessing from their keys is not enough:
    /// traffic, tcp, udp, hosts, bench or scenario.
    #[arg(long, value_name = "KIND")]
    kind: Option<FileKind>,

    /// Set a scenario variable, as for `ferotrx scenario run`.
    #[arg(long = "set", value_name = "NAME=VALUE", value_parser = crate::scenario::parse_var)]
    vars: Vec<(String, String)>,

    /// Fail on warnings too.
    #[arg(long)]
    strict: bool,

    /// Print only problems.
    #[arg(short, long)]
    quiet: bool,
}

pub fn cmd_check(args: CheckArgs) -> Result<()> {
    let (mut errors, mut warned) = (0, 0);
    for file in &args.files {
        let name = file.display();
        match check_file(file, args.kind, &args.vars) {
            Ok(c) => {
                let kind = c.kind.map_or("file", FileKind::as_str);
                if c.warnings.is_empty() {
                    println!("{name}: ok ({kind})");
                } else {
                    warned += 1;
                    println!("{name}: ok ({kind}), {} warning(s)", c.warnings.len());
                }
                if !args.quiet {
                    for line in &c.summary {
                        println!("  {line}");
                    }
                }
                for w in &c.warnings {
                    println!("  warning: {w}");
                }
            }
            Err(e) => {
                errors += 1;
                println!("{name}: error: {e}");
            }
        }
    }
    if errors > 0 {
        bail!("{errors} of {} file(s) have errors", args.files.len());
    }
    if args.strict && warned > 0 {
        bail!("{warned} file(s) have warnings (--strict)");
    }
    Ok(())
}
