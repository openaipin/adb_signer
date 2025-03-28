use base64::{prelude::BASE64_STANDARD, Engine};
use num_bigint::ModInverse;
use num_traits::{cast::FromPrimitive, ToPrimitive};
use rsa::{traits::PublicKeyParts, BigUint, RsaPrivateKey};
use worker::*;

const ADB_PRIVATE_KEY_SIZE: usize = 2048;
const ANDROID_PUBKEY_MODULUS_SIZE_WORDS: u32 = 64;

// adb_client
// Copyright (c) 2023-2024 Corentin LIAUD
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#[repr(C)]
#[derive(Debug, Default)]
/// Internal ADB representation of a public key
struct ADBRsaInternalPublicKey {
    pub modulus_size_words: u32,
    pub n0inv: u32,
    pub modulus: BigUint,
    pub rr: Vec<u8>,
    pub exponent: u32,
}

impl ADBRsaInternalPublicKey {
    pub fn new(exponent: &BigUint, modulus: &BigUint) -> Result<Self> {
        Ok(Self {
            modulus_size_words: ANDROID_PUBKEY_MODULUS_SIZE_WORDS,
            exponent: exponent
                .to_u32()
                .ok_or(Error::RustError("Conversion error".to_string()))?,
            modulus: modulus.clone(),
            ..Default::default()
        })
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.append(&mut self.modulus_size_words.to_le_bytes().to_vec());
        bytes.append(&mut self.n0inv.to_le_bytes().to_vec());
        bytes.append(&mut self.modulus.to_bytes_le());
        bytes.append(&mut self.rr);
        bytes.append(&mut self.exponent.to_le_bytes().to_vec());

        bytes
    }
}

pub fn android_pubkey_encode(private_key: RsaPrivateKey) -> Result<String> {
    // Helped from project: https://github.com/hajifkd/webadb
    // Source code: https://android.googlesource.com/platform/system/core/+/refs/heads/main/libcrypto_utils/android_pubkey.cpp
    // Useful function `android_pubkey_encode()`
    let mut adb_rsa_pubkey = ADBRsaInternalPublicKey::new(private_key.e(), private_key.n())?;

    // r32 = 2 ^ 32
    let r32 = BigUint::from_u64(1 << 32).ok_or(Error::RustError("Conversion error".to_string()))?;

    // r = 2 ^ rsa_size = 2 ^ 2048
    let r = set_bit(ADB_PRIVATE_KEY_SIZE)?;

    // rr = r ^ 2 mod N
    let rr = r.modpow(&BigUint::from(2u32), &adb_rsa_pubkey.modulus);
    adb_rsa_pubkey.rr = rr.to_bytes_le();

    // rem = N[0]
    let rem = &adb_rsa_pubkey.modulus % &r32;

    // n0inv = -1 / rem mod r32
    let n0inv = rem
        .mod_inverse(&r32)
        .and_then(|v| v.to_biguint())
        .ok_or(Error::RustError("Conversion error".to_string()))?;

    // BN_sub(n0inv, r32, n0inv)
    adb_rsa_pubkey.n0inv = (r32 - n0inv)
        .to_u32()
        .ok_or(Error::RustError("Conversion error".to_string()))?;

    Ok(encode_public_key(adb_rsa_pubkey.into_bytes()))
}

fn encode_public_key(pub_key: Vec<u8>) -> String {
    let mut encoded = BASE64_STANDARD.encode(pub_key);
    encoded.push(' ');
    encoded.push_str(&format!("adb_client@{}", env!("CARGO_PKG_VERSION")));

    encoded
}

fn set_bit(n: usize) -> Result<BigUint> {
    BigUint::parse_bytes(
        &{
            let mut bits = vec![b'1'];
            bits.append(&mut vec![b'0'; n]);
            bits
        }[..],
        2,
    )
    .ok_or(Error::RustError("Conversion error".to_string()))
}
