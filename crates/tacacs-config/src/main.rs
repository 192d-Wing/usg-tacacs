// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use usg_tacacs_config::ServerConfiguration;

#[derive(Debug, Parser)]
#[command(
    name = "usg-tacacs-config-check",
    version,
    about = "Validate a typed USG TACACS YAML server configuration"
)]
struct Args {
    /// YAML server configuration to validate.
    #[arg(value_name = "CONFIG")]
    config: PathBuf,

    /// Also require every referenced certificate, key, CA, and secret file to exist.
    #[arg(long)]
    check_files: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config = ServerConfiguration::from_path(&args.config)?;
    config.validate(args.check_files)?;
    println!("configuration validated: {}", args.config.display());
    Ok(())
}
