use aes::Aes256;
use ctr::cipher::KeyIvInit;
use ctr::cipher::StreamCipher;
use rand::{RngCore, SeedableRng};
use ring::hmac;
use serde::Deserialize;
use serde::Serialize;

pub fn generate_key(length: usize) -> Vec<u8> {
	let mut dest = vec![0; length];
    rand::rngs::StdRng::from_entropy().fill_bytes(&mut dest);
    dest
}

#[derive(Default, Serialize, Deserialize)]
pub struct AESCTRHelper {
    pub aes_key: Vec<u8>,
    pub hmac_key: Vec<u8>,
}

impl AESCTRHelper {
    pub fn new() -> AESCTRHelper {
        return AESCTRHelper{
            aes_key:  generate_key(32),
            hmac_key: generate_key(32),
        }
    }

    pub fn encrypt(&self, plaintext: Vec<u8>) -> Vec<u8> {
        let mut iv = &mut generate_key(16);
        let key: [u8; 32] = self.aes_key.clone().try_into().unwrap();

        let key = aes_gcm::Key::<Aes256>::clone_from_slice(&key);

        let mut ciphertext = vec![0; plaintext.len()];

        let mut cipher = ctr::Ctr64BE::<aes::Aes256>::new_from_slices(&key, &iv).unwrap();


        cipher
                .apply_keystream_b2b(&plaintext, &mut ciphertext)
                .unwrap();

        ciphertext.append(&mut iv);

        let mac = hmac::Key::new(hmac::HMAC_SHA256, &self.hmac_key);
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
    
        let mac = hmac::Key::new(hmac::HMAC_SHA256, &self.hmac_key);
        if hmac::verify(&mac, encrypted_data_without_hmac, hmac_signature).is_err() {
            panic!("HMAC mismatch");
        }
    
        let iv = &encrypted_data_without_hmac[encrypted_data_without_hmac.len()-16..];

        encrypted_data_without_hmac = &encrypted_data_without_hmac[..encrypted_data_without_hmac.len()-16];
    
        let mut cipher = ctr::Ctr64BE::<aes::Aes256>::new_from_slices(&self.aes_key, &iv).unwrap();
        let mut decrypted_data = vec![0; encrypted_data_without_hmac.len()];
        cipher.apply_keystream_b2b(&encrypted_data_without_hmac, &mut decrypted_data).unwrap();
    
        return decrypted_data
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod test {
    use protobuf::Message;

    use crate::protos::{client::{ReceiveMessagesRequest, SendMessageRequest}, rpc::{OutgoingRPCData, OutgoingRPCMessage}};

    use super::AESCTRHelper;

    #[test]
    fn encrypt_decrypt() {
        let plaintext = "Hello World".as_bytes().to_vec();
        let crypto = AESCTRHelper::new();
        let ciphertext = crypto.encrypt(plaintext);
        let decrypted = crypto.decrypt(ciphertext);
        println!("{}", String::from_utf8_lossy(&decrypted));
        
    }

    #[test]
    fn go_encrypt() {
        let go_ciphertext = base64::decode("20JcWPhcGHS6PmsBGxrxZIPrhUVnUkUUs5c8UwDNRXTogBUln0kOkYtD9+39SleRwarILSWOQ9/3iT1kw3G8os6oonzal1o6Nm7QhkZ3NKEb7rYZWzmiiFSIQjh1/8w8ROx0ztFiHy5D/opi4lag4DIQgpMddaNLo3n0jRBLJu7LtXCKS0IlBZSW07dJDd26lxkniLMbzPgCGRzMw3q6BxLWs6nW6YN8cjB2YVj4ipiEFXmi6FmGRLC7wIZBiJZS+hRnbnL0Ped8KlCVYr8bZuBWP9QU/fthixyID0ntzWLKii6oWePcWQymJtAg4sGnSqpfGE1NeYaVVK8aRSIDxDfiKdiQZFcZgWIdFS0ofWAY91m/pjvJTCAkKvwG9fOapIO77hIrc45BatzYmfOI26EM2e7rAoPl+tu7fIpssxz86oXd6vIlJPbGY0MZUOIz/j+wAo33ipTIVot2frDydv4WtJ1KwAo3xgzt2AW6khTuazt2LBFXj25uYBJeFPm2gGxd5LylG4ZC6JYhon2fZFdvzgjtYEFcFZPL3onN+VviF+YPbzO1opyS0O9F60ehl4fBmP1gMa6M7AiSl1pzzuh7PHqpC0i6hFXrH/bKKZdXtCF+6BHN3CnTwj8GpH6u+HsYm4kLiD3wj3jmYP+UAIs2SDbPJQ7khe2r7B0BuU0UaXE2nrTVInvcbyvauRhJ6Djuv8Xl+9Oh51OygO68Rr9TsGlNZ4JT95yUOTAXyl1tjlGyQhPRxu/QyPpi7HryPpw2RBn6iR5xEnDDijF22816ZtfLzum7wFtCuvZ5uwhBlyLrqpALVZBf8ZKsog==").unwrap();
        let crypto = AESCTRHelper {
            aes_key: base64::decode("vIYkvvx6mbmr94dmGLkvGMVmrRCEXWsTcpaGMadx7mU=").unwrap(),
            hmac_key: base64::decode("/McGUYgViOW/5m/orqeuecz3Wv+PXkB25fiYlGXys7Y=").unwrap(),
        };
        // let ciphertext = crypto.encrypt(plaintext);
        let decrypted = crypto.decrypt(go_ciphertext);
        println!("{}", String::from_utf8_lossy(&decrypted));
    }

    #[test]
    fn phone_encrypt() {
        let phone_ciphertext = base64::decode("VKywr8ckKC63srhmiRj2GjWwvGP6wvd/ha1zi7I/afiswuPFUXL9CegIxYdxAGRvFiK6XgCrBh0nXT8QTlRRaCGJp3uWaBHcdmkebTbBp9ZDz97LVBYVhdnqh1IfpalILYAHPL+ldOJpxuZf5VTslLD+TuvQg8omyKmuV992GxGKXsrLkooLVlAoDJ5/+Q2JwE6aIvIfgEwfxQwdS4t4dSMzK4X2s5fX13wrQ68NFy5ttS3Ud5GVtOdUWh2adSkcb4DJUyY1ktB5zYXD2riYUcZDkpw8eFapzUBbgVUmqhyjqee+QdO/p9bqs/LQBP1jetu/w5YPjOXy5DTAGkGICHlVrFpE4Fa7jkcNC3OwR3rhV0zjh+IM8Ucj3R8S6olW5uaS2ZUz4XItkPhtwHIaUBqyj6hg4DEL1MrB37VUZBd5y3GHtvxZ5gan0M1L8L1tcT10rij1rv9JqE17iKbPNU3SPtjvZIB+nBml5IEkxHVF9a/SJ9A51bJn4wTyMUqBtdnVOMqpefY6OJyeAVf2F7YnfTj3pEMxgcMpBVgs4U1WXsQndV/ZxgH8t7zTqOawdcfWE8HJSOYklzMO7klmOO8clatuJyM9wvtxvLZ41i0=").unwrap();
        let crypto = AESCTRHelper {
            aes_key: base64::decode("vIYkvvx6mbmr94dmGLkvGMVmrRCEXWsTcpaGMadx7mU=").unwrap(),
            hmac_key: base64::decode("/McGUYgViOW/5m/orqeuecz3Wv+PXkB25fiYlGXys7Y=").unwrap(),
        };
        // let ciphertext = crypto.encrypt(plaintext);
        let decrypted = crypto.decrypt(phone_ciphertext);
        println!("{}", String::from_utf8_lossy(&decrypted));
    }

    #[test]
    fn go_decrypt() {
        let crypto = AESCTRHelper {
            aes_key: base64::decode("vIYkvvx6mbmr94dmGLkvGMVmrRCEXWsTcpaGMadx7mU=").unwrap(),
            hmac_key: base64::decode("/McGUYgViOW/5m/orqeuecz3Wv+PXkB25fiYlGXys7Y=").unwrap(),
        };
        let plaintext = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.".as_bytes().to_vec();
        let ciphertext = crypto.encrypt(plaintext);
        println!("{}", base64::encode(&ciphertext));
    }

    #[test]
    fn keygen() {
        let crypto = AESCTRHelper::new();
        println!("aes: {}", base64::encode(&crypto.aes_key));
        println!("hmac: {}", base64::encode(&crypto.hmac_key));
    }

    #[test]
    fn decrypt_web_req() {
        let crypto = AESCTRHelper {
            aes_key: base64::decode("83nxSx6kjEuxJBYC2M7egf0IXW3iuVDmfRGrICs1uqI=").unwrap(),
            hmac_key: base64::decode("rehRi6hvjczvK5KVGftoo0FeZaw/GUakRnvpxPU6WNw=").unwrap(),
        };
        let message = "[[13,\"+1-auFcNdpZudG3UvGQMBE1o80\",\"Bugle\"],[\"8c668dcc-9fd9-217c-97fa-5ff052ce989a\",19,null,null,null,null,null,null,null,null,null,\"CiQ4YzY2OGRjYy05ZmQ5LTIxN2MtOTdmYS01ZmYwNTJjZTk4OWEQAyqaAQ1nRzbZwtIGy9IJTlPShd0qKfeKPgAAJNlhywNEts8nyjX06VU78SfyJuE74E98ZtZnPHkH2/rZnBMXotYsVtGEYLU5K7q5oEgzGbEPbhlibMc79ggjnbKXMlluu9AfQDu/dPnpdHIwHpuqjWeSwQ8pGeIUJmEPIvj6kkksGkWZWo2jV63nMWTEtc/bJ3IHvC2h3ixHFkajsy8yJGNiZDg5NDFlLWFlNDMtNjMyMi03NTNhLTY4MmU1MmNlOTg5YQ==\",null,null,null,null,null,null,null,null,null,null,[null,2]],[\"8c668dcc-9fd9-217c-97fa-5ff052ce989a\",null,null,null,null,\"AH8pFRJOBw3DAbC2VkewfcXZZDdWyEs7RzlzUui833akPfuc+uRj+bKTmGH3no14Y0oqkWoWQi6xxWWANj+I8WgC2XAVwTj5O0q405/ihF0H6pkiSHEpMd/iUnkie43RRWRIGdTVQQEQdTxrDny8Yls2+AQO+my4ZYs=\",[null,null,2024,12,9,null,4,null,6]]]";
        let mut rpc_message = OutgoingRPCMessage::default();
        pblite_rust::deserialize::unmarshal(&message, &mut rpc_message).unwrap();
        println!("rpc message: {}", protobuf_json_mapping::print_to_string(&rpc_message).unwrap());
        let rpc_data = OutgoingRPCData::parse_from_bytes(&rpc_message.data.messageData).unwrap();
        println!("rpc data: {}", protobuf_json_mapping::print_to_string(&rpc_data).unwrap());
        let decrypted_bytes = crypto.decrypt(rpc_data.encryptedProtoData.clone());
        println!("{}", base64::encode(&decrypted_bytes));
        let decrypted_message = SendMessageRequest::parse_from_bytes(&decrypted_bytes).unwrap();
        println!("encrypted message: {}", protobuf_json_mapping::print_to_string(&decrypted_message).unwrap());
    }

    #[test]
    fn test_unmarshal() {
        let value = "[[\"107dd469-7139-66d1-4f9b-81a353ab6199\",null,null,null,null,\"AH8pFRJOBw3DAbC2VkewfcXZZDdWyEs7RzlzUui833akPfuc+uRj+bKTmGH3no14Y0oqkWoWQi6xxWWANj+I8WgC2XAVwTj5O0q405/ihF0H6pkiSHEpMd/iUnkie43RRWRIGdTVQQEQdTxrDny8Yls2+AQO+my4ZYs=\",[null,null,2024,12,9,null,4,null,6]],null,null,[]]";
        let message = &mut ReceiveMessagesRequest::default();
        pblite_rust::deserialize::unmarshal(&value, message).unwrap();
        println!("decoded: {}", protobuf_json_mapping::print_to_string(message).unwrap());
    }
}