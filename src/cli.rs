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
use clap::{Arg, ArgMatches, Command};

pub fn parse_args() -> ArgMatches {
    Command::new("Wabasen")
        .version("0.1.1")
        .about("\nCopyright (C) 2024 Sinodevi\nWabasen comes with ABSOLUTELY NO WARRANTY\nThis is a free software, and you are welcome to distribute it,\nunder certain conditions. See the LICENSE file or\nGNU General Public License version 3\non https://www.gnu.org/licenses/ for details.\n\nOpen source software for file encryption with wallet-based 2FA.")
        .after_help("Documentation: wabasen.com")
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("encrypt")
                .about("Encrypt files or folders using wallet-based 2FA")
                .arg(
                    Arg::new("input")
                        .short('i')
                        .long("input")
                        .value_name("INPUT")
                        .required(true)
                        .help("Input path of file or folder"),
                )
                .arg(
                    Arg::new("address")
                        .short('a')
                        .long("address")
                        .value_name("ADDRESS")
                        .required(true)
                        .help("Address wallet linked to the signature"),
                )
                .arg(
                    Arg::new("password")
                        .short('p')
                        .long("password")
                        .value_name("PASSWORD")
                        .required(true)
                        .default_value("password")
                        .help("Password signed by the wallet"),
                )
                .arg(
                    Arg::new("signature")
                        .short('s')
                        .long("signature")
                        .value_name("SIGNATURE")
                        .required(true)
                        .help("Signature of the password performed by the wallet"),
                ),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt files encrypted with wallet-based 2FA")
                .arg(
                    Arg::new("input")
                        .short('i')
                        .long("input")
                        .value_name("INPUT")
                        .required(true)
                        .help("Input path of encrypted file"),
                )
                .arg(
                    Arg::new("address")
                        .short('a')
                        .long("address")
                        .value_name("ADDRESS")
                        .required(true)
                        .help("Address wallet linked to the signature"),
                )
                .arg(
                    Arg::new("password")
                        .short('p')
                        .long("password")
                        .value_name("PASSWORD")
                        .required(true)
                        .default_value("password")
                        .help("Password signed by the wallet"),
                )
                .arg(
                    Arg::new("signature")
                        .short('s')
                        .long("signature")
                        .value_name("SIGNATURE")
                        .required(true)
                        .help("Signature of the password performed by the wallet"),
                ),
        ).get_matches()
}
