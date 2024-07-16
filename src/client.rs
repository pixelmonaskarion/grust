use core::panic;
use std::{io::BufWriter, sync::Arc, time::{Duration, SystemTime}};

use base64::Engine;
use jsonwebkey::{JsonWebKey, Key, X509Params};
use pblite_rust::serialize::marshal;
use protobuf::MessageField;
use reqwest::cookie::Jar;
use ring::pkcs8;
use uuid::Uuid;
use x509_cert::der::Encode;
use crate::{protos::authentication::{authentication_container, AuthenticationContainer, BrowserDetails, BrowserType, DeviceType, ECDSAKeys, KeyData}, INSTANT_MESSAGING_BASE_URL, PAIRING_BASE_URL, QR_CODE_URL_BASE, QR_NETWORK, REGISTER_PHONE_RELAY_URL, USER_AGENT};
use crate::{crypto::AESCTRHelper, protos::{authentication::{sign_in_gaia_request, AuthMessage, ConfigVersion, Device, RegisterPhoneRelayResponse, SignInGaiaRequest, SignInGaiaResponse, TokenData, URLData}, config::Config}, CONFIG_URL, GOOGLE_NETWORK, INSTANT_MESSAGING_BASE_URLGOOGLE, REGISTRATION_BASE_URL, SIGN_IN_GAIA_URL};

pub struct Client {
    pub auth_data: AuthData,
    pub http_client: reqwest::Client,
    pub config: Config,
}

pub struct AuthData {
    pub request_crypto: AESCTRHelper,
    pub session_id: Uuid,
    pub refresh_key: JsonWebKey,
    pub tachyon_auth_token: Vec<u8>,
    pub tachyon_expiry: SystemTime,
    pub tachyon_ttl: Duration,
    pub mobile: Device,
    pub browser: Device,
}

pub struct PrimaryDeviceID {
	reg_id: String,
	unknown_int: u64,
}

impl Client {
    pub async fn new() -> Self {
        let mut _self = Self {
            auth_data: AuthData {
                request_crypto: AESCTRHelper::new(), 
                session_id: Uuid::default(),
                refresh_key: JsonWebKey::new(Key::generate_p256()),
                tachyon_auth_token: vec![],
                tachyon_expiry: SystemTime::UNIX_EPOCH,
                tachyon_ttl: Duration::ZERO,
                mobile: Device::default(),
                browser: Device::default(),
            },
            http_client: reqwest::Client::new(),
            config: Config::default(),
        };
        _self.config = _self.fetch_config().await;
        let device_id = &_self.config.deviceInfo.deviceID;
        if !device_id.is_empty() {
            _self.auth_data.session_id = Uuid::parse_str(&device_id).unwrap();
        }
        return _self;
    }

    pub async fn fetch_config(&self) -> Config {
        let req = self.http_client.get(CONFIG_URL);
        let res = self.http_client.execute(req.build().unwrap()).await.unwrap();
        let res_body = &res.text().await.unwrap();
        let mut config = Config::default();
        pblite_rust::deserialize::unmarshal(&res_body, &mut config).unwrap();
        return config;
    }

    pub async fn do_gaia_pairing(&mut self, cookies: &str) {
        //worry about cookies later
        let gaia_resp = self.sign_in_gaia_get_token(cookies).await;
        let mut primary_devices = vec![];
        for device in gaia_resp.deviceData.unknownItems2.clone() {
            if device.unknownInt4 == 1 {
                primary_devices.push(PrimaryDeviceID {
                    reg_id: device.destOrSourceUUID,
                    unknown_int: device.unknownBigInt7,
                });
            }
        }
        if primary_devices.len() == 0 {
            panic!("no devices found!");
        }
        let dest_reg_id = &primary_devices[0]; // maybe choose one later?
        let dest_reg_uuid: Uuid = dest_reg_id.reg_id.parse().unwrap();
        println!("{dest_reg_uuid}");
    } 

    pub async fn sign_in_gaia_get_token(&mut self, cookies: &str) -> SignInGaiaResponse {
        let key = self.auth_data.refresh_key.key.to_public().unwrap().try_to_der().unwrap();
        let mut payload = self.base_sign_in_gaia_payload();
        payload.inner.as_mut().unwrap().someData = MessageField::some(sign_in_gaia_request::inner::Data {
            someData: key,
            ..Default::default()
        });
        let req = self.http_client.post(INSTANT_MESSAGING_BASE_URLGOOGLE.to_string()+REGISTRATION_BASE_URL+SIGN_IN_GAIA_URL)
            .body(serde_json::to_string(&pblite_rust::serialize::marshal(&mut payload)).unwrap())
            .header("Content-Type", "application/json+protobuf")
            .header("Cookie", cookies)
            // .header("X-Goog-Api-Key", "AIzaSyCA4RsOZUFrm9whhtGosPlJLmVPnfSHKz8")
            // .header("X-Goog-Authuser", "0")
            // .bearer_auth(&oauth_token)
            .build().unwrap();
        let res = self.http_client.execute(req).await.unwrap().text().await.unwrap();
        println!("{res}");
        let mut gaia_resp = SignInGaiaResponse::default();
        pblite_rust::deserialize::unmarshal(&res, &mut gaia_resp).unwrap();
        self.update_tachyon_auth_token(*gaia_resp.tokenData.0.clone().unwrap());
        let device = &gaia_resp.deviceData.deviceWrapper.device;
        let mut lowercase_device = *device.clone().0.unwrap();
        lowercase_device.sourceID = device.sourceID.to_lowercase();
        self.auth_data.mobile = lowercase_device;
        self.auth_data.browser = *device.0.clone().unwrap();
        return gaia_resp;
    }

    fn base_sign_in_gaia_payload(&self) -> SignInGaiaRequest {
        return SignInGaiaRequest {
            authMessage: MessageField::some(AuthMessage {
                requestID:     Uuid::new_v4().to_string(),
                network:       GOOGLE_NETWORK.into(),
                configVersion: MessageField::some(ConfigVersion {
                    Year: 2024,
                    Month: 5,
                    Day: 9,
                    V1: 4,
                    V2: 6,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            inner: MessageField::some(sign_in_gaia_request::Inner{
                deviceID: MessageField::some(sign_in_gaia_request::inner::DeviceID{
                    unknownInt1: 3,
                    deviceID:    format!("messages-web-{}", hex::encode(self.auth_data.session_id.as_bytes())),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            network: GOOGLE_NETWORK.into(),
            ..Default::default()
        }
    }

    fn update_tachyon_auth_token(&mut self, data: TokenData) {
        self.auth_data.tachyon_auth_token = data.tachyonAuthToken;
        let mut valid_for_duration = Duration::from_secs(data.TTL as u64);
        if valid_for_duration.is_zero() {
            valid_for_duration = Duration::from_secs(24 * 60 * 60);
        }
        self.auth_data.tachyon_expiry = SystemTime::now() + valid_for_duration;
        self.auth_data.tachyon_ttl = valid_for_duration;
    }

    pub async fn start_login(&mut self) -> String {
        let registered = self.register_phone_relay().await;
        self.update_tachyon_auth_token(*registered.authKeyData.0.unwrap());
        // self.do_long_poll(false, None);
        let qr = self.generate_qr_code_data(registered.pairingKey);
        return qr;
    }

    async fn register_phone_relay(&self) -> RegisterPhoneRelayResponse {
        let key_pem = self.auth_data.refresh_key.key.to_public().unwrap().to_pem();
        println!("{key_pem}");
        let key_cert = x509_cert::Certificate::load_pem_chain(key_pem.as_bytes()).unwrap();
        let key = key_cert.get(0).unwrap();
        let mut buf = BufWriter::new(Vec::new());
        key.encode(&mut buf).unwrap();
        let bytes = buf.into_inner().unwrap();
        let key_pkix = String::from_utf8(bytes).unwrap();
        let mut payload = AuthenticationContainer {
            authMessage: MessageField::some(AuthMessage {
                requestID: Uuid::new_v4().to_string(),
                network: QR_NETWORK.into(),
                configVersion: MessageField::some(ConfigVersion {
                    Year:  2024,
                    Month: 5,
                    Day:   9,
                    V1:    4,
                    V2:    6,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            browserDetails: MessageField::some(BrowserDetails {
                userAgent:   USER_AGENT.into(),
                browserType: BrowserType::OTHER.into(),
                OS:          "libgm".to_string(),
                deviceType:  DeviceType::TABLET.into(),
                ..Default::default()
            }),
            data: Some(authentication_container::Data::KeyData(KeyData {
                ecdsaKeys: MessageField::some(ECDSAKeys {
                    field1: 2,
                    encryptedKeys: key_pkix.into_bytes(),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let req = self.http_client.post(INSTANT_MESSAGING_BASE_URL.to_string()+PAIRING_BASE_URL+REGISTER_PHONE_RELAY_URL)
            .body(serde_json::to_string(&pblite_rust::serialize::marshal(&mut payload)).unwrap())
            .header("Content-Type", "application/json+protobuf")
            .build().unwrap();
        let res = self.http_client.execute(req).await.unwrap().text().await.unwrap();
        let mut reg_res = RegisterPhoneRelayResponse::default();
        pblite_rust::deserialize::unmarshal(&res, &mut reg_res).unwrap();
        return reg_res;
    }

    fn generate_qr_code_data(&self, pairing_key: Vec<u8>) -> String {
        let mut url_data = URLData {
            pairingKey: pairing_key,
            AESKey: self.auth_data.request_crypto.AESkey.clone(),
            HMACKey: self.auth_data.request_crypto.HMACkey.clone(),
            ..Default::default()
        };
        let encoded_url_data = marshal(&mut url_data).to_string();
        let c_data = base64::engine::general_purpose::STANDARD.encode(encoded_url_data.as_bytes());
        return format!("{QR_CODE_URL_BASE}{c_data}");
    }
}