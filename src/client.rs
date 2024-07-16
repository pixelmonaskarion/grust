use core::panic;
use std::{fmt::format, future::Future, io::BufWriter, sync::Arc, time::{Duration, SystemTime}};

use base64::Engine;
use hex::ToHex;
use jsonwebkey::{JsonWebKey, Key, X509Params};
use protobuf::{Message, MessageField};
use reqwest::{cookie::Jar, IntoUrl, Method, RequestBuilder, Response, StatusCode};
use ring::{digest::SHA256, pkcs8, rand::SystemRandom, signature::{self, EcdsaSigningAlgorithm}};
use tokio::{sync::Mutex, task::JoinHandle};
use uuid::Uuid;
use x509_cert::der::{Decode, Encode};
use crate::{protos::{authentication::{authentication_container, register_refresh_request::NestedEmptyArr, AuthenticationContainer, BrowserDetails, BrowserType, DeviceType, ECDSAKeys, KeyData, RegisterRefreshRequest, RegisterRefreshResponse}, client::{receive_messages_request::UnknownEmptyObject2, ReceiveMessagesRequest}, rpc::LongPollingPayload, util::EmptyArr}, INSTANT_MESSAGING_BASE_URL, MESSAGING_BASE_URL, PAIRING_BASE_URL, QR_CODE_URL_BASE, QR_NETWORK, RECEIVE_MESSAGES_URL, REGISTER_PHONE_RELAY_URL, USER_AGENT};
use crate::{crypto::AESCTRHelper, protos::{authentication::{sign_in_gaia_request, AuthMessage, ConfigVersion, Device, RegisterPhoneRelayResponse, SignInGaiaRequest, SignInGaiaResponse, TokenData, URLData}, config::Config}, CONFIG_URL, GOOGLE_NETWORK, INSTANT_MESSAGING_BASE_URLGOOGLE, REGISTRATION_BASE_URL, SIGN_IN_GAIA_URL};
use crate::REGISTER_REFRESH_URL;
use futures_util::StreamExt;

pub struct Client {
    pub auth_data: AuthData,
    pub http_client: reqwest::Client,
    pub config: Config,

    pub listen_id: i32,
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
            listen_id: 0,
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
        let req = self.new_request(Method::POST, INSTANT_MESSAGING_BASE_URLGOOGLE.to_string()+REGISTRATION_BASE_URL+SIGN_IN_GAIA_URL)
            .body(payload.write_to_bytes().unwrap())
            .header("Content-Type", "application/x-protobuf")
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
                configVersion: MessageField::some(configVersion()),
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

    pub async fn start_login(_self: Arc<Mutex<Self>>) -> (String, JoinHandle<anyhow::Result<()>>) {
        let registered = _self.lock().await.register_phone_relay().await;
        println!("{registered}");
        _self.lock().await.update_tachyon_auth_token(*registered.authKeyData.0.unwrap());
        let handle = tokio::spawn(Self::do_long_poll(_self.clone(), false));
        let qr = _self.lock().await.generate_qr_code_data(registered.pairingKey);
        return (qr, handle);
    }

    async fn register_phone_relay(&self) -> RegisterPhoneRelayResponse {
        let key_der = self.auth_data.refresh_key.key.to_public().unwrap().to_der();
        let mut payload = AuthenticationContainer {
            authMessage: MessageField::some(AuthMessage {
                requestID: Uuid::new_v4().to_string(),
                network: QR_NETWORK.into(),
                tachyonAuthToken: self.auth_data.tachyon_auth_token.clone(),
                configVersion: MessageField::some(configVersion()),
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
                    encryptedKeys: key_der,
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let req = self.new_request(Method::POST, INSTANT_MESSAGING_BASE_URL.to_string()+PAIRING_BASE_URL+REGISTER_PHONE_RELAY_URL)
            .body(payload.write_to_bytes().unwrap())
            .header("Content-Type", "application/x-protobuf")
            .build().unwrap();
        let res = self.http_client.execute(req).await.unwrap().bytes().await.unwrap();
        let reg_res = RegisterPhoneRelayResponse::parse_from_bytes(&res).unwrap();
        return reg_res;
    }

    fn generate_qr_code_data(&self, pairing_key: Vec<u8>) -> String {
        let url_data = URLData {
            pairingKey: pairing_key,
            AESKey: self.auth_data.request_crypto.AESkey.clone(),
            HMACKey: self.auth_data.request_crypto.HMACkey.clone(),
            ..Default::default()
        };
        let c_data = base64::engine::general_purpose::STANDARD.encode(url_data.write_to_bytes().unwrap());
        return format!("{QR_CODE_URL_BASE}{c_data}");
    }

    async fn do_long_poll(_self: Arc<Mutex<Self>>, logged_in: bool) -> anyhow::Result<()>{
        _self.lock().await.listen_id += 1;
        let listen_id = _self.lock().await.listen_id;
        let listen_req_id = Uuid::new_v4().to_string();
        let mut errorCount = 1;
        while _self.lock().await.listen_id == listen_id {
            let err = _self.lock().await.refresh_auth_token().await;
            if err.is_err() {
                if logged_in {
                    err?;
                }
            }
            let payload = ReceiveMessagesRequest {
                auth: MessageField::some(AuthMessage {
                    requestID: listen_req_id.clone(),
                    tachyonAuthToken: _self.lock().await.auth_data.tachyon_auth_token.clone(),
                    network: "".into(),
                    configVersion: MessageField::some(configVersion()),
                    ..Default::default()
                }),
                unknown: MessageField::some(UnknownEmptyObject2::new()),
                ..Default::default()
            };
            let url = format!("{INSTANT_MESSAGING_BASE_URL}{MESSAGING_BASE_URL}{RECEIVE_MESSAGES_URL}");
            let req = _self.lock().await.new_request(Method::POST, url)
                .body(payload.write_to_bytes()?)
                .header("Content-Type", "application/x-protobuf")
                .build()?;
            let res = _self.lock().await.http_client.execute(req).await;
            if res.is_err() {
                //TODO
            }
            let res = res?;
            if res.status() != StatusCode::OK {
                //TODO
            }
            Self::read_long_poll(_self.clone(), res).await;
        }
        Ok(())
    }

    async fn read_long_poll(_self: Arc<Mutex<Self>>, res: Response) {
        println!("reading long poll!");
        let mut bytes_stream = res.bytes_stream();
        let mut pending_message_bytes: Vec<u8> = vec![];
        while let Some(Ok(chunk)) = bytes_stream.next().await {
            for byte in &chunk {
                pending_message_bytes.push(*byte);
                if let Ok(msg) = LongPollingPayload::parse_from_bytes(&pending_message_bytes) {
                    println!("got message: {msg}");
                    pending_message_bytes = vec![];
                }
            }
        }
    }

    async fn refresh_auth_token(&mut self) -> anyhow::Result<()> {
        if self.auth_data.tachyon_expiry.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO) > Duration::from_secs(60*60) {
            return Ok(());
        }
        let jwk = &self.auth_data.refresh_key;
        let request_id = Uuid::new_v4().to_string();
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis() * 1000;
        let sign_bytes = ring::digest::digest(&SHA256, format!("{request_id}:{timestamp}").as_bytes());
        
        let sig = ring::signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, jwk.key.to_pem().as_bytes(), &ring::rand::SystemRandom::new()).unwrap()
            .sign(&SystemRandom::new(), sign_bytes.as_ref()).unwrap();
        let payload = RegisterRefreshRequest {
            messageAuth: MessageField::some(AuthMessage {
                requestID: request_id,
                tachyonAuthToken: self.auth_data.tachyon_auth_token.clone(),
                network: "".into(),
                configVersion: MessageField::some(configVersion()),
                ..Default::default()
            }),
            currBrowserDevice: MessageField::some(self.auth_data.browser.clone()),
            unixTimestamp: timestamp as i64,
            signature: sig.as_ref().to_vec(),
            emptyRefreshArr: MessageField::some(NestedEmptyArr::default()),
            messageType: 2,
            ..Default::default()
        };
        let req = self.new_request(Method::POST, format!("{INSTANT_MESSAGING_BASE_URLGOOGLE}{REGISTRATION_BASE_URL}{REGISTER_REFRESH_URL}"))
            .body(payload.write_to_bytes().unwrap())
            .header("Content-Type", "application/x-protobuf")
            .build().unwrap();
        let res_bytes = self.http_client.execute(req).await?.bytes().await?;
        let res = RegisterRefreshResponse::parse_from_bytes(&res_bytes)?;
        self.update_tachyon_auth_token(*res.tokenData.0.unwrap());
        Ok(())
    }
    
    fn new_request<U: reqwest::IntoUrl>(&self, method: reqwest::Method, url: U) -> RequestBuilder {
        self.http_client.request(method, url)
            .header("sec-ch-ua", SEC_UA)
            .header("x-user-agent", X_USER_AGENT)
            .header("x-goog-api-key", GOOGLE_API_KEY)
            .header("sec-ch-ua-mobile", SEC_UA_MOBILE)
            .header("user-agent", USER_AGENT)
            .header("sec-ch-ua-platform", format!("\"{UA_PLATFORM}\""))
            .header("origin", "https://messages.google.com")
            .header("sec-fetch-site", "cross-site")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-dest", "empty")
            .header("referer", "https://messages.google.com/")
            .header("accept-language", "en-US,en;q=0.9")
    }

    async fn typed_api_call<U: IntoUrl, T: Message>(&self, url: U, message: &impl Message) -> anyhow::Result<T> {
        let req = self.new_request(Method::POST, url)
            .body(message.write_to_bytes()?)
            .header("Content-Type", "application/x-protobuf")
            .build()?;
        let res_bytes = self.http_client.execute(req).await?.bytes().await?;
        return Ok(T::parse_from_bytes(&res_bytes)?);
    }
}

const UA_PLATFORM: &'static str = "Android";
const SEC_UA: &'static str = r#""Google Chrome";v="123", "Chromium";v="123", "Not-A.Brand";v="24""#;
const X_USER_AGENT: &'static str = "grpc-web-javascript/0.1";
const GOOGLE_API_KEY: &'static str = "AIzaSyCA4RsOZUFrm9whhtGosPlJLmVPnfSHKz8"; //from beeper
const SEC_UA_MOBILE: &'static str = "?1";

fn configVersion() -> ConfigVersion {
    ConfigVersion {
        Year: 2024,
        Month: 5,
        Day: 9,
        V1: 4,
        V2: 6,
        ..Default::default()
    }
}