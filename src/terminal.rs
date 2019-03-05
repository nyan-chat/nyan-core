use openssl::rsa::{Padding, Rsa};
use openssl::pkey::Private;
use openssl::hash::{hash_xof, MessageDigest};
use crate::{device::Device};

const RSA_LENGTH: u32 = 4096;

pub struct Terminal {
    device: Device,
    privkey: Rsa<Private>,
}

impl Terminal {
    pub fn generate(name: String) -> Terminal {
        let key_pair = Rsa::generate(RSA_LENGTH).unwrap();
        let pubkey = Rsa::public_key_from_der(&key_pair.public_key_to_der().unwrap()).unwrap();
        let privkey = key_pair;
        let device = Device::new(name, pubkey);
        Terminal { device: device, privkey: privkey }
    }

    pub fn key_bits(&self) -> u32 {
        RSA_LENGTH
    }

    pub fn export_public_key(&self) -> Vec<u8> {
        self.privkey.public_key_to_der().unwrap()
    }

    pub fn export_private_key(&self) -> Vec<u8> {
        self.privkey.private_key_to_der().unwrap()
    }

    pub fn encrypt_key(&self) {

    }

    pub fn decrypt_key(&self) {

    }

    pub fn sign(&self, msg: &Vec<u8>) -> Vec<u8> {
        let mut hashed = vec![0; self.privkey.size() as usize];
        hash_xof(MessageDigest::shake_256(), msg, hashed.as_mut_slice()).unwrap();
        let mut signed = vec![0; self.privkey.size() as usize];
        self.privkey.private_encrypt(&hashed, &mut signed, Padding::NONE).unwrap();
        signed
    }
}
