// Copyright (C) 2026 Cercano Contributors
//
// This file is part of Cercano.
//
// Cercano is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Cercano is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Cercano. If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-only

use cercano_audit::{export_database, load_verifying_key, print_summary, verify_file};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "cercano-audit",
    version = "0.1.0",
    about = "Offline verification and management tool for Cercano audit trails"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Verify cryptographic hash chain and checkpoint signatures of an audit stream
    Verify {
        /// Path to the audit JSONL file to verify
        file: PathBuf,

        /// Optional Ed25519 public key (hex string or path to .pub file)
        #[arg(long)]
        pubkey: Option<String>,

        /// Detailed per-event output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Export an SQLite audit database to a verifiable JSONL file
    ExportDb {
        /// Path to the SQLite database file
        db_path: PathBuf,

        /// Path to the output JSONL file
        output_jsonl: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify {
            file,
            pubkey,
            verbose,
        } => {
            let verifying_key = if let Some(ref pk_input) = pubkey {
                match load_verifying_key(pk_input) {
                    Ok(vk) => Some(vk),
                    Err(err) => {
                        eprintln!("Error loading public key: {}", err);
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                None
            };

            match verify_file(&file, verifying_key.as_ref(), verbose) {
                Ok(summary) => {
                    let mut stdout = std::io::stdout();
                    let _ = print_summary(&summary, &mut stdout);

                    if summary.is_valid {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(err) => {
                    eprintln!("Verification failed to execute: {}", err);
                    ExitCode::FAILURE
                }
            }
        }
        Commands::ExportDb {
            db_path,
            output_jsonl,
        } => match export_database(&db_path, &output_jsonl).await {
            Ok((events, checkpoints)) => {
                println!(
                    "Successfully exported {} events and {} checkpoints to {}",
                    events,
                    checkpoints,
                    output_jsonl.display()
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("Export failed: {}", err);
                ExitCode::FAILURE
            }
        },
    }
}
