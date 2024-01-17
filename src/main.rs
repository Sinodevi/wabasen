/*
Open source software for file encryption with wallet-based 2FA.
Copyright (C) 2024 Sinodevi

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Please send bugreports with examples or suggestions to: wabasen@sinodevi.com
*/
mod cli;
use clap::ArgMatches;
use cli::parse_args;
use std::process;

use wabasen::{decrypt, encrypt};

fn main() -> () {
    let matches: ArgMatches = parse_args();

    match matches.subcommand() {
        Some(("encrypt", args)) => {
            let input: &str = match args.get_one::<String>("input") {
                Some(input) => input,
                None => {
                    eprintln!("Error: {}", "input option is required");
                    process::exit(1);
                }
            };

            let signature: &str = match args.get_one::<String>("signature") {
                Some(signature) => signature,
                None => {
                    eprintln!("Error: {}", "signature option is required");
                    process::exit(1);
                }
            };

            let password: &str = match args.get_one::<String>("password") {
                Some(password) => password,
                None => {
                    eprintln!("Error: {}", "password option is required");
                    process::exit(1);
                }
            };

            let address: &str = match args.get_one::<String>("address") {
                Some(address) => address,
                None => {
                    eprintln!("Error: {}", "address option is required");
                    process::exit(1);
                }
            };

            match encrypt(input, address, signature, password) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            };
        }
        Some(("decrypt", args)) => {
            let input: &str = match args.get_one::<String>("input") {
                Some(input) => input,
                None => {
                    eprintln!("Error: {}", "input option is required");
                    process::exit(1);
                }
            };

            let signature: &str = match args.get_one::<String>("signature") {
                Some(signature) => signature,
                None => {
                    eprintln!("Error: {}", "signature option is required");
                    process::exit(1);
                }
            };

            let password: &str = match args.get_one::<String>("password") {
                Some(password) => password,
                None => {
                    eprintln!("Error: {}", "password option is required");
                    process::exit(1);
                }
            };

            let address: &str = match args.get_one::<String>("address") {
                Some(address) => address,
                None => {
                    eprintln!("Error: {}", "address option is required");
                    process::exit(1);
                }
            };

            match decrypt(input, address, signature, password) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            };
        }
        _ => {
            eprintln!("Error: {}", "no specific subcommand");
            process::exit(1);
        }
    }
}
