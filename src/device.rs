use openssl::rsa::{Padding, Rsa};
use openssl::pkey::Public;
use openssl::hash::{hash_xof, MessageDigest};
use crate::{consts::Consts, errors::Errors};

pub struct Device {
    name: String,
    pubkey: Rsa<Public>,
}

impl Device {
    pub fn new(name: String, pubkey: Rsa<Public>) -> Device {
        Device { name: name, pubkey: pubkey }
    }

    pub fn import_from_der(name: String, pubkey: Vec<u8>) -> Result<Device, Errors> {
        let rsa = Rsa::public_key_from_der(&pubkey);
        match rsa {
            Ok(val) => Ok(Device { name: name, pubkey: val }),
            Err(_) => Err(Errors { val: -1, reason: "Failed To Parse the Public Key" }),
        }
    }

    pub fn info(&self) -> &String {
        &self.name
    }

    pub fn decrypt_key(&self, encrypted_key: &Vec<u8>) -> Result<Vec<u8>, Errors> {
        let mut buf = vec![0; self.pubkey.size() as usize];
        match self.pubkey.public_decrypt(&encrypted_key, &mut buf, Padding::PKCS1) {
            Ok(_) => Ok(buf[..Consts::AES_KEY_SIZE].to_vec()),
            Err(_) => Err(Errors { val: -1, reason: "Failed to Decrypt with Public Key"}),
        }
    }

    pub fn validate(&self, msg: &Vec<u8>, signature: &Vec<u8>) -> bool {
        let mut hashed = vec![0; self.pubkey.size() as usize];
        hash_xof(MessageDigest::shake_256(), msg, hashed.as_mut_slice()).unwrap();
        let mut decrypted = vec![0; self.pubkey.size() as usize];
        match self.pubkey.public_decrypt(&signature, &mut decrypted, Padding::NONE) {
            Ok(_) => hashed == decrypted,
            Err(_) => false,
        }
    }
}
