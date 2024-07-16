use aes_gcm::{aes::{cipher::BlockEncrypt, Aes128, Aes256}, KeyInit};
use rand::{RngCore, SeedableRng};
use ring::hmac;

pub fn generate_key(length: usize) -> Vec<u8> {
	let mut dest = vec![0; length];
    rand::rngs::StdRng::from_entropy().fill_bytes(&mut dest);
    dest
}

#[derive(Default)]
pub struct AESCTRHelper {
    pub AESkey: Vec<u8>,
    pub HMACkey: Vec<u8>,
}

impl AESCTRHelper {
    pub fn new() -> AESCTRHelper {
        return AESCTRHelper{
            AESkey:  generate_key(32),
            HMACkey: generate_key(32),
        }
    }

    pub fn encrypt(&self, plaintext: Vec<u8>) -> Vec<u8> {
        let mut iv = &mut generate_key(16);
        let key: [u8; 32] = self.AESkey.clone().try_into().unwrap();

        let key = aes_gcm::Key::<Aes256>::from_slice(&key);

        let cipher = Aes256::new(&key);
        let mut ciphertext = vec![];

        plaintext.chunks(iv.len()).for_each(|chunk| {
            let mut block = aes_gcm::Key::<Aes128>::from_slice(chunk).clone();
            cipher.encrypt_block(&mut block);
            ciphertext.append(&mut block.to_vec());
        });
        ciphertext.append(&mut iv);

        let mac = hmac::Key::new(hmac::HMAC_SHA256, &self.HMACkey);
        let signiture = hmac::sign(&mac, &ciphertext);
        ciphertext.append(&mut signiture.as_ref().to_vec());

        return ciphertext;
    }

    pub fn decrypt(&self, encrypted_data: Vec<u8>) -> Vec<u8> {
        if encrypted_data.len() < 48 {
            panic!("input data is too short");
        }
    
        let hmac_signature = &encrypted_data[encrypted_data.len()-32..];
        let mut encrypted_data_without_hmac = &encrypted_data[..encrypted_data.len()-32];
    
        let mac = hmac::Key::new(hmac::HMAC_SHA256, &self.HMACkey);
        if hmac::verify(&mac, encrypted_data_without_hmac, hmac_signature).is_err() {
            panic!("HMAC mismatch");
        }
    
        let iv = &encrypted_data_without_hmac[encrypted_data_without_hmac.len()-16..];

        encrypted_data_without_hmac = &encrypted_data_without_hmac[..encrypted_data_without_hmac.len()-16];
    
        let key: [u8; 32] = self.AESkey.clone().try_into().unwrap();

        let key = aes_gcm::Key::<Aes256>::from_slice(&key);

        let cipher = Aes256::new(&key);
        let mut decrypted_data = vec![];
        encrypted_data_without_hmac.chunks(iv.len()).for_each(|chunk| {
            let mut block = aes_gcm::Key::<Aes128>::from_slice(chunk).clone();
            cipher.encrypt_block(&mut block);
            decrypted_data.append(&mut block.to_vec());
        });
    
        return decrypted_data
    }
}