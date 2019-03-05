use openssl::rsa::{Padding, Rsa};
use openssl::pkey::Public;
use openssl::hash::{hash_xof, MessageDigest};

pub struct Device {
    name: String,
    pubkey: Rsa<Public>,
}

impl Device {
    pub fn new(name: String, pubkey: Rsa<Public>) -> Device {
        Device { name: name, pubkey: pubkey }
    }

    pub fn import_from_der(name: String, pubkey: Vec<u8>) -> Device {
        // TODO: Import may fail, add error information if possible
        Device { name: name, pubkey: Rsa::public_key_from_der(&pubkey).unwrap() }
    }

    pub fn info(&self) -> &String {
        &self.name
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

