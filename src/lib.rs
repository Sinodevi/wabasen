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
use chacha20poly1305::{
    aead::{stream, KeyInit},
    XChaCha20Poly1305,
};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use hex::decode;
use indicatif::{MultiProgress, ProgressBar};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    All, Message, PublicKey, Secp256k1,
};
use std::{
    fs::{metadata, remove_dir_all, remove_file, File},
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};
use tar::{Archive, Builder};
use tiny_keccak::{Hasher, Keccak};

pub fn encrypt(
    from_path: &str,
    address: &str,
    signature: &str,
    password: &str,
) -> Result<(), String> {
    println!("\nEncrypt '{}'\n", from_path);

    let start_time: Instant = Instant::now();

    let progress: MultiProgress = MultiProgress::new();

    match verify_password_from_signature(address, password, signature) {
        Ok(s) => s,
        Err(e) => return Err(e),
    };

    let path: &Path = Path::new(from_path);

    let to_path: &str = match path.file_stem() {
        Some(file_stem) => match file_stem.to_str() {
            Some(file_stem_str) => file_stem_str,
            None => return Err(format!("The file name is not valid UTF-8 ({})", from_path)),
        },
        None => {
            return Err(format!(
                "The path does not include a valid file name ({})",
                from_path
            ))
        }
    };

    let compressed_archive_path: String = format!("{}_temp", to_path);

    let final_path: String = format!("{}.waba", to_path);

    let compress_bar: ProgressBar = progress.add(ProgressBar::new_spinner());

    compress_bar.enable_steady_tick(Duration::from_millis(100));
    compress_bar.set_message("[1/2] Compressing...");

    let compress_start_time: Instant = Instant::now();

    match compress(from_path, &compressed_archive_path) {
        Ok(s) => s,
        Err(e) => {
            if metadata(&compressed_archive_path).is_ok() {
                match remove_file(&compressed_archive_path) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(format!(
                            "Failed to delete the temporary file ({})",
                            compressed_archive_path
                        ))
                    }
                };
            }
            return Err(e);
        }
    };

    let compress_elapsed_time = compress_start_time.elapsed();

    compress_bar.finish_with_message(format!(
        "[1/2] Compression completed ({:?})",
        compress_elapsed_time
    ));

    let encrypt_bar: ProgressBar = progress.add(ProgressBar::new_spinner());

    encrypt_bar.enable_steady_tick(Duration::from_millis(100));
    encrypt_bar.set_message("[2/2] Encryption...");

    let encrypt_start_time: Instant = Instant::now();

    match encrypt_file(&compressed_archive_path, &final_path, signature, password) {
        Ok(s) => s,
        Err(e) => {
            if metadata(&compressed_archive_path).is_ok() {
                match remove_file(&compressed_archive_path) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(format!(
                            "Failed to delete the temporary file ({})",
                            compressed_archive_path
                        ))
                    }
                };
            }
            if metadata(&final_path).is_ok() {
                match remove_file(&final_path) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(format!(
                            "Failed to delete the encrypted file ({})",
                            final_path
                        ))
                    }
                };
            }

            return Err(e);
        }
    };

    match remove_file(&compressed_archive_path) {
        Ok(s) => s,
        Err(_) => {
            if metadata(&final_path).is_ok() {
                match remove_file(&final_path) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(format!(
                            "Failed to delete the encrypted file ({})",
                            final_path
                        ))
                    }
                };
            }

            return Err(format!(
                "Failed to delete the temporary file ({})",
                compressed_archive_path
            ));
        }
    };

    let from_path_data: &Path = Path::new(from_path);

    if from_path_data.is_file() {
        match remove_file(from_path) {
            Ok(s) => s,
            Err(_) => return Err(format!("Failed to delete input ({})", from_path)),
        };
    } else if from_path_data.is_dir() {
        match remove_dir_all(from_path) {
            Ok(s) => s,
            Err(_) => return Err(format!("Failed to delete input directory ({})", from_path)),
        };
    } else {
        return Err(format!("Invalid input path ({})", from_path));
    }

    let encrypt_elapsed_time: Duration = encrypt_start_time.elapsed();

    encrypt_bar.finish_with_message(format!(
        "[2/2] Encryption completed ({:?})",
        encrypt_elapsed_time
    ));

    let elapsed_time: Duration = start_time.elapsed();

    println!(
        "\n\n'{}' is encrypted to '{}' in {:?}",
        from_path, final_path, elapsed_time
    );

    return Ok(());
}

fn encrypt_file(
    from_path: &str,
    to_path: &str,
    signature: &str,
    password: &str,
) -> Result<(), String> {
    let nonce: [u8; 19] = generate_nonce_from_password(password);
    let key: [u8; 32] = generate_key_from_signature(signature);
    let aead = XChaCha20Poly1305::new(key.as_ref().into());

    let mut stream_encryptor: stream::Encryptor<_, stream::StreamBE32<_>> =
        stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
    let mut buffer: [u8; 4096] = [0u8; 4096];

    let mut source_file: File = match File::open(from_path) {
        Ok(f) => f,
        Err(_) => return Err(format!("Failed to open input file ({})", from_path)),
    };

    let mut dist_file: File = match File::create(&to_path) {
        Ok(f) => f,
        Err(_) => return Err(format!("Failed to create output file ({})", to_path)),
    };

    loop {
        let read_count: usize = match source_file.read(&mut buffer) {
            Ok(f) => f,
            Err(_) => return Err(format!("Failed to read input file ({})", from_path)),
        };

        if read_count == 4096 {
            let ciphertext: Vec<u8> = match stream_encryptor.encrypt_next(buffer.as_slice()) {
                Ok(f) => f,
                Err(_) => return Err(format!("Failed to encrypt file ({})", from_path)),
            };

            match dist_file.write(&ciphertext) {
                Ok(f) => f,
                Err(_) => return Err(format!("Failed to write file ({})", to_path)),
            };
        } else {
            let ciphertext: Vec<u8> = match stream_encryptor.encrypt_last(&buffer[..read_count]) {
                Ok(f) => f,
                Err(_) => return Err(format!("Failed to encrypt file ({})", from_path)),
            };

            match dist_file.write(&ciphertext) {
                Ok(f) => f,
                Err(_) => return Err(format!("Failed to write file ({})", to_path)),
            };
            break;
        }
    }

    return Ok(());
}

fn compress(from_path: &str, to_path: &str) -> Result<(), String> {
    let archive_file: File = match File::create(&to_path) {
        Ok(f) => f,
        Err(_) => return Err(format!("Failed to create output file ({})", to_path)),
    };

    let encoder: GzEncoder<File> = GzEncoder::new(archive_file, Compression::default());

    let mut archive: Builder<GzEncoder<File>> = Builder::new(encoder);

    let from_path_data: &Path = Path::new(from_path);

    if from_path_data.is_file() {
        match archive.append_path(from_path) {
            Ok(f) => f,
            Err(_) => {
                return Err(format!("Failed to archive input file ({})", from_path));
            }
        };
    } else if from_path_data.is_dir() {
        match archive.append_dir_all("", from_path) {
            Ok(f) => f,
            Err(_) => {
                return Err(format!("Failed to archive input folder ({})", from_path));
            }
        };
    } else {
        return Err(format!("Invalid input path ({})", from_path));
    }

    return Ok(());
}

pub fn decrypt(
    from_path: &str,
    address: &str,
    signature: &str,
    password: &str,
) -> Result<(), String> {
    println!("\nDecrypt '{}' \n", from_path);

    let start_time: Instant = Instant::now();

    let progress: MultiProgress = MultiProgress::new();

    match verify_password_from_signature(address, password, signature) {
        Ok(s) => s,
        Err(e) => return Err(e),
    };

    let path: &Path = Path::new(from_path);

    let to_path: &str = match path.file_stem() {
        Some(file_stem) => match file_stem.to_str() {
            Some(file_stem_str) => file_stem_str,
            None => return Err(format!("The file name is not valid UTF-8 ({})", from_path)),
        },
        None => {
            return Err(format!(
                "The path does not include a valid file name ({})",
                from_path
            ))
        }
    };

    let compressed_archive_path: String = format!("{}_temp", to_path);

    let decrypt_bar: ProgressBar = progress.add(ProgressBar::new_spinner());

    decrypt_bar.enable_steady_tick(Duration::from_millis(100));
    decrypt_bar.set_message("[1/2] Decryption...");

    let decrypt_start_time: Instant = Instant::now();

    match decrypt_file(from_path, &compressed_archive_path, signature, password) {
        Ok(s) => s,
        Err(e) => {
            if metadata(&compressed_archive_path).is_ok() {
                match remove_file(&compressed_archive_path) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(format!(
                            "Failed to delete the temporary file ({})",
                            compressed_archive_path
                        ));
                    }
                };
            }
            return Err(e);
        }
    };

    let decrypt_elapsed_time: Duration = decrypt_start_time.elapsed();

    decrypt_bar.finish_with_message(format!(
        "[1/2] Decryption completed ({:?})",
        decrypt_elapsed_time
    ));

    let decompress_bar: ProgressBar = progress.add(ProgressBar::new_spinner());

    decompress_bar.enable_steady_tick(Duration::from_millis(100));
    decompress_bar.set_message("[2/2] Decompressing...");

    let decompress_start_time: Instant = Instant::now();

    match decompress(&compressed_archive_path, to_path) {
        Ok(s) => s,
        Err(e) => {
            if metadata(&compressed_archive_path).is_ok() {
                match remove_file(&compressed_archive_path) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(format!(
                            "Failed to delete the temporary file ({})",
                            compressed_archive_path
                        ));
                    }
                };
            }
            if metadata(&to_path).is_ok() {
                match remove_file(&to_path) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(format!("Failed to delete the decrypted file ({})", to_path));
                    }
                };
            }
            return Err(e);
        }
    };

    match remove_file(&compressed_archive_path) {
        Ok(s) => s,
        Err(_) => {
            if metadata(&to_path).is_ok() {
                match remove_file(&to_path) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(format!("Failed to delete the decrypted file ({})", to_path));
                    }
                };
            }
            return Err(format!(
                "Failed to delete the temporary file ({})",
                compressed_archive_path
            ));
        }
    };

    match remove_file(from_path) {
        Ok(s) => s,
        Err(_) => {
            return Err(format!("Failed to delete input file ({})", from_path));
        }
    };

    let decompress_elapsed_time: Duration = decompress_start_time.elapsed();

    decompress_bar.finish_with_message(format!(
        "[2/2] Decompression completed ({:?})",
        decompress_elapsed_time
    ));

    let elapsed_time: Duration = start_time.elapsed();

    println!(
        "\n\n'{}' is decrypted to '{}' in {:?}",
        from_path, to_path, elapsed_time
    );

    return Ok(());
}

fn decompress(from_path: &str, to_path: &str) -> Result<(), String> {
    let archive_file: File = match File::open(&from_path) {
        Ok(f) => f,
        Err(_) => return Err(format!("Failed to open input ({})", from_path)),
    };

    let decoder: GzDecoder<File> = GzDecoder::new(archive_file);

    let mut archive: Archive<GzDecoder<File>> = Archive::new(decoder);

    match archive.unpack(to_path) {
        Ok(f) => f,
        Err(_) => return Err(format!("Failed to archive input ({})", from_path)),
    };

    Ok(())
}

fn decrypt_file(
    from_path: &str,
    to_path: &str,
    signature: &str,
    password: &str,
) -> Result<(), String> {
    let nonce: [u8; 19] = generate_nonce_from_password(password);
    let key: [u8; 32] = generate_key_from_signature(signature);
    let aead = XChaCha20Poly1305::new(key.as_ref().into());

    let mut stream_decryptor: stream::Decryptor<_, stream::StreamBE32<_>> =
        stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());
    let mut buffer: [u8; 4112] = [0u8; 4112];

    let mut source_file: File = match File::open(from_path) {
        Ok(f) => f,
        Err(_) => return Err(format!("Failed to open input file ({})", from_path)),
    };

    let mut dist_file: File = match File::create(to_path) {
        Ok(f) => f,
        Err(_) => return Err(format!("Failed to create output file ({})", to_path)),
    };

    loop {
        let read_count: usize = match source_file.read(&mut buffer) {
            Ok(f) => f,
            Err(_) => return Err(format!("Failed to read input file ({})", from_path)),
        };

        if read_count == 4112 {
            let plaintext: Vec<u8> = match stream_decryptor.decrypt_next(buffer.as_slice()) {
                Ok(f) => f,
                Err(_) => return Err(format!("Failed to decrypt file ({})", from_path)),
            };

            match dist_file.write(&plaintext) {
                Ok(f) => f,
                Err(_) => return Err(format!("Failed to save write ({})", to_path)),
            };
        } else if read_count == 0 {
            break;
        } else {
            let plaintext: Vec<u8> = match stream_decryptor.decrypt_last(&buffer[..read_count]) {
                Ok(f) => f,
                Err(_) => return Err(format!("Failed to decrypt file ({})", from_path)),
            };

            match dist_file.write(&plaintext) {
                Ok(f) => f,
                Err(_) => return Err(format!("Failed to write file ({})", to_path)),
            };
            break;
        }
    }

    Ok(())
}

fn verify_password_from_signature(
    address: &str,
    password: &str,
    signature: &str,
) -> Result<(), String> {
    let address: String = address.to_string().to_lowercase();
    let password_hash: [u8; 32] = hash_message(password.to_string());

    let signature_vec: Vec<u8> = match decode(&signature[2..]) {
        Ok(s) => s,
        Err(_) => return Err(format!("Invalid signature format ({})", signature)),
    };

    let recovery_id: i32 = signature_vec[64] as i32 - 27;

    let pubkey: String = match recover(&password_hash, &signature_vec[..64], recovery_id) {
        Ok(s) => s,
        Err(_) => {
            return Err(format!(
                "Invalid public key format ({}{}{:?})",
                password, signature, recovery_id
            ))
        }
    };

    if !(address == pubkey) {
        return Err(format!(
            "Invalid signature ({}) of password ({}) for wallet ({})",
            signature, password, address
        ));
    } else {
        return Ok(());
    }
}

fn recover(message: &[u8], signature: &[u8], recovery_id: i32) -> Result<String, String> {
    let secp256k1: Secp256k1<All> = Secp256k1::new();
    let message: Message = match Message::from_digest_slice(message) {
        Ok(s) => s,
        Err(_) => return Err(format!("Invalid message format ({:?})", message)),
    };

    let recovery_id: RecoveryId = match RecoveryId::from_i32(recovery_id) {
        Ok(s) => s,
        Err(_) => return Err(format!("Invalid recovery_id format ({:?})", recovery_id)),
    };

    let signature: RecoverableSignature =
        match RecoverableSignature::from_compact(signature, recovery_id) {
            Ok(s) => s,
            Err(_) => return Err(format!("Invalid signature format ({:?})", signature)),
        };

    let public_key: PublicKey = match secp256k1.recover_ecdsa(&message, &signature) {
        Ok(s) => s,
        Err(_) => {
            return Err(format!(
                "Failed to retrieve ecdsa public key ({:?})",
                signature
            ))
        }
    };

    let public_key: [u8; 65] = public_key.serialize_uncompressed();

    let hash: [u8; 32] = keccak256(&public_key[1..]);

    let address_part: &[u8] = &hash[12..32];

    let mut address: String = String::from("0x");
    address.push_str(&hex::encode(address_part));

    return Ok(address);
}

fn generate_key_from_signature(key_str: &str) -> [u8; 32] {
    let mut key: [u8; 32] = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(key_str.as_bytes());
    hasher.finalize(&mut key);
    key
}

fn generate_nonce_from_password(password: &str) -> [u8; 19] {
    let mut nonce: [u8; 19] = [0u8; 19];
    let mut hasher = Keccak::v256();
    hasher.update(password.as_bytes());
    hasher.finalize(&mut nonce);
    nonce
}

fn hash_message(message: String) -> [u8; 32] {
    keccak256(
        format!(
            "{}{}{}",
            "\x19Ethereum Signed Message:\n",
            message.len(),
            message
        )
        .as_bytes(),
    )
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut output: [u8; 32] = [0u8; 32];
    let mut hasher: Keccak = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}
