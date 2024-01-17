# Wabasen

Open source cross-platform software for file encryption with wallet-based 2FA

---

## [Website](https://wabasen.com) | [Documentation](https://wabasen.com/intro)

---

## Introduction

We developed this software to meet the essential requirements for security and convenience in managing sensitive data. Our solution, built in [Rust](https://www.rust-lang.org/) and functioning as a command-line interface ([CLI](https://en.wikipedia.org/wiki/Command-line_interface)), offers a suite of vital features aimed at preserving the confidentiality and integrity of encrypted files and folders.

Primarily, our software creates [TAR](<https://en.wikipedia.org/wiki/Tar_(computing)>) archives of specified files or folders, subsequently compressing them with [Gzip](https://en.wikipedia.org/wiki/Gzip) to optimize storage space. Following this, it encrypts the archive using the [XChaCha20Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) algorithm, renowned for its robust security and performance.

What sets our solution apart is its [two-factor authentication system](https://blog.sinodevi.com/wallet-based-2fa), combining a password with the signature of an [Ethereum](https://ethereum.org/) wallet for data access. This dual authentication enhances security, akin to the approach employed by [YubiKeys](https://www.yubico.com/), but with the additional benefit of a [Ledger](https://www.ledger.com/) key. This [Ledger](https://www.ledger.com/) key not only streamlines financial management but also grants access to encrypted files. With the increasing popularity of secure electronic wallets like [Ledger](https://www.ledger.com/) keys, offering exceptionally high levels of security, our solution becomes all-encompassing. Users can enjoy the convenience of a unified system where both their finances and sensitive data are protected using the same secure method. This not only enhances convenience and efficiency but also ensures an optimal level of security.

This system ensures that data remains inaccessible to individuals without both the password and the associated [Ethereum](https://ethereum.org/) wallet, significantly enhancing data security.

Furthermore, our software boasts several technical advantages. With a compact size of only **6.5 MB**, it is lightweight and easily distributable. Thanks to [Rust](https://www.rust-lang.org/), it is also swift and resilient, guaranteeing optimal performance across all major operating systems, including [Windows](https://www.microsoft.com/en-us/windows), [macOS](https://www.apple.com/macos), and [Linux](https://www.linux.org/).

In summary, our software offers a comprehensive and secure solution for archiving, compressing, and encrypting sensitive data, leveraging the latest advancements in electronic wallet security. With its lightweight, fast, and robust interface, our solution provides a seamless user experience across all major operating systems.

## Usage

```
USAGE:
    wabasen [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    decrypt    Decrypt files encrypted with wallet-based 2FA
    encrypt    Encrypt files or folders using wallet-based 2FA
    help       Prints this message or the help of the given subcommand(s)

Documentation: wabasen.com
```

#### Encrypt

```
USAGE:
    wabasen encrypt --address <ADDRESS> --input <INPUT> --password <PASSWORD> --signature <SIGNATURE>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -a, --address <ADDRESS>        Address wallet linked to the signature
    -i, --input <INPUT>            Input path of file or folder
    -p, --password <PASSWORD>      Password signed by the wallet [default: password]
    -s, --signature <SIGNATURE>    Signature of the password performed by the wallet

Documentation: wabasen.com
```

#### Decrypt

```
USAGE:
    wabasen decrypt --address <ADDRESS> --input <INPUT> --password <PASSWORD> --signature <SIGNATURE>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -a, --address <ADDRESS>        Address wallet linked to the signature
    -i, --input <INPUT>            Input path of encrypted file
    -p, --password <PASSWORD>      Password signed by the wallet [default: password]
    -s, --signature <SIGNATURE>    Signature of the password performed by the wallet

Documentation: wabasen.com
```

## License

SEE LICENSE IN [LICENSE](LICENSE)

---

Open source software for file encryption with wallet-based 2FA.
Copyright (C) 2024 Sinodevi

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

Please send bugreports with examples or suggestions to: wabasen@sinodevi.com
