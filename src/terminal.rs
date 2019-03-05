use openssl::rsa::{Padding, Rsa};
use openssl::pkey::Private;
use openssl::hash::{hash_xof, MessageDigest};
use crate::{device::Device, consts::Consts};

pub struct Terminal {
    device: Device,
    privkey: Rsa<Private>,
}

impl Terminal {
    pub fn generate(name: String) -> Terminal {
        let key_pair = Rsa::generate(Consts::RSA_LENGTH).unwrap();
        let pubkey = Rsa::public_key_from_der(&key_pair.public_key_to_der().unwrap()).unwrap();
        let privkey = key_pair;
        let device = Device::new(name, pubkey);
        Terminal { device: device, privkey: privkey }
    }

    pub fn key_bits(&self) -> u32 {
        Consts::RSA_LENGTH
    }

    pub fn get_device(&self) -> &Device {
        &self.device
    }

    pub fn export_public_key(&self) -> Vec<u8> {
        self.privkey.public_key_to_der().unwrap()
    }

    pub fn export_private_key(&self) -> Vec<u8> {
        self.privkey.private_key_to_der().unwrap()
    }

    pub fn encrypt_key(&self, key: &Vec<u8>) -> Vec<u8> {
        if key.len() != Consts::AES_KEY_SIZE {
            panic!("Incorrenct chacha20-ietf-poly1305 key size")
        }
        let mut buf = vec![0; self.privkey.size() as usize];
        self.privkey.private_encrypt(&key, &mut buf, Padding::PKCS1).unwrap();
        buf
    }

    pub fn sign(&self, msg: &Vec<u8>) -> Vec<u8> {
        let mut hashed = vec![0; self.privkey.size() as usize];
        hash_xof(MessageDigest::shake_256(), msg, hashed.as_mut_slice()).unwrap();
        let mut signed = vec![0; self.privkey.size() as usize];
        self.privkey.private_encrypt(&hashed, &mut signed, Padding::NONE).unwrap();
        signed
    }
}
