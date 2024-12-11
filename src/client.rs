use core::panic;
use std::{collections::HashMap, fmt::Debug, sync::Arc, time::{Duration, SystemTime}};

use base64::Engine;
use jsonwebkey::{JsonWebKey, Key};
use log::{debug, info, trace, warn};
use protobuf::{Enum, Message, MessageDyn, MessageField};
use reqwest::{IntoUrl, Method, RequestBuilder, Response, StatusCode};
use ring::{digest::SHA256, rand::SystemRandom, signature::{self}};
use serde::{Deserialize, Serialize};
use tokio::{sync::{oneshot::{self, Sender}, Mutex}, task::JoinHandle, time::sleep};
use uuid::Uuid;
use crate::protos::{authentication::{authentication_container, register_refresh_request::NestedEmptyArr, AuthenticationContainer, BrowserDetails, BrowserType, DeviceType, ECDSAKeys, KeyData, PairedData, RegisterRefreshRequest, RegisterRefreshResponse}, client::{ack_message_request, receive_messages_request::UnknownEmptyObject2, AckMessageRequest, DeleteMessageResponse, GetConversationResponse, GetConversationTypeResponse, GetOrCreateConversationResponse, GetThumbnailResponse, IsBugleDefaultResponse, ListContactsResponse, ListConversationsResponse, ListMessagesResponse, ListTopContactsResponse, NotifyDittoActivityResponse, ReceiveMessagesRequest, SendMessageResponse, SendReactionResponse, UpdateConversationResponse}, events::{RPCPairData, UpdateEvents}, rpc::{outgoing_rpcmessage, ActionType, BugleRoute, IncomingRPCMessage, LongPollingPayload, MessageType, OutgoingRPCData, OutgoingRPCMessage, OutgoingRPCResponse, RPCMessageData}};
use crate::{crypto::AESCTRHelper, protos::{authentication::{sign_in_gaia_request, AuthMessage, ConfigVersion, Device, RegisterPhoneRelayResponse, SignInGaiaRequest, SignInGaiaResponse, TokenData, URLData}, config::Config}};
use crate::consts::{REGISTER_REFRESH_URL, ACK_MESSAGES_URL, INSTANT_MESSAGING_BASE_URL, MESSAGING_BASE_URL, PAIRING_BASE_URL, QR_CODE_URL_BASE, QR_NETWORK, RECEIVE_MESSAGES_URL, REGISTER_PHONE_RELAY_URL, SEND_MESSAGE_URL, USER_AGENT, CONFIG_URL, GOOGLE_NETWORK, INSTANT_MESSAGING_BASE_URLGOOGLE, REGISTRATION_BASE_URL, SIGN_IN_GAIA_URL};
use futures_util::StreamExt;

#[derive(Serialize, Deserialize)]
pub struct Client {
    pub auth_data: AuthData,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub http_client: reqwest::Client,
    #[serde(serialize_with = "crate::serialize_proto", deserialize_with = "crate::deserialize_proto")]
    pub config: Config,

    pub listen_id: i32,
    #[serde(skip_serializing, skip_deserializing, default = "return_none")]
    pub conn_handle: Option<JoinHandle<anyhow::Result<()>>>,
    pub ack_messages: Vec<String>,
    pub session_id: String,

    #[serde(skip_serializing, skip_deserializing, default = "return_none")]
    pub pairing_complete: Option<Sender<bool>>,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub pending_messages: HashMap<String, oneshot::Sender<ActionMessage>>,
}

fn return_none<T>() -> Option<T> {
    None
}

#[derive(Serialize, Deserialize)]
pub struct AuthData {
    pub request_crypto: AESCTRHelper,
    pub session_id: Uuid,
    pub refresh_key: JsonWebKey,
    pub tachyon_auth_token: Vec<u8>,
    pub tachyon_expiry: SystemTime,
    pub tachyon_ttl: Duration,
    #[serde(serialize_with = "crate::serialize_proto", deserialize_with = "crate::deserialize_proto")]
    pub mobile: Device,
    #[serde(serialize_with = "crate::serialize_proto", deserialize_with = "crate::deserialize_proto")]
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
            conn_handle: None,
            ack_messages: vec![],
            session_id: Uuid::new_v4().to_string(),
            pairing_complete: None,
            pending_messages: HashMap::new(),
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
        debug!("{dest_reg_uuid}");
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
        debug!("{res}");
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
                configVersion: MessageField::some(config_version()),
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

    pub async fn start_login(_self: Arc<Mutex<Self>>) -> String {
        let registered = _self.lock().await.register_phone_relay().await;
        debug!("registration response: {registered}");
        _self.lock().await.update_tachyon_auth_token(*registered.authKeyData.0.unwrap());
        let handle = tokio::spawn(Self::do_long_poll(_self.clone(), false, false, None));
        _self.lock().await.conn_handle = Some(handle);
        let qr = _self.lock().await.generate_qr_code_data(registered.pairingKey);
        return qr;
    }

    async fn register_phone_relay(&self) -> RegisterPhoneRelayResponse {
        let key_der = self.auth_data.refresh_key.key.to_public().unwrap().to_der();
        let mut payload = AuthenticationContainer {
            authMessage: MessageField::some(AuthMessage {
                requestID: Uuid::new_v4().to_string(),
                network: QR_NETWORK.into(),
                tachyonAuthToken: self.auth_data.tachyon_auth_token.clone(),
                configVersion: MessageField::some(config_version()),
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

    async fn do_long_poll(_self: Arc<Mutex<Self>>, logged_in: bool, post_connect: bool, mut connected_tx: Option<oneshot::Sender<bool>>) -> anyhow::Result<()>{
        _self.lock().await.listen_id += 1;
        let listen_id = _self.lock().await.listen_id.clone();
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
                    network: "".into(), //blank or GDitto for google auth
                    configVersion: MessageField::some(config_version()),
                    ..Default::default()
                }),
                unknown: MessageField::some(UnknownEmptyObject2::new()),
                ..Default::default()
            };
            let url = format!("{INSTANT_MESSAGING_BASE_URL}{MESSAGING_BASE_URL}{RECEIVE_MESSAGES_URL}");
            let req = _self.lock().await.new_request(Method::POST, url)
                .body(pblite_rust::serialize::marshal(&payload).to_string())
                .header("Content-Type", "application/json+protobuf")
                .build()?;
            let res = _self.lock().await.http_client.execute(req).await;
            if res.is_err() {
                if let Some(connected_tx) = connected_tx {
                    connected_tx.send(true).unwrap();
                }
                return Ok(());
            }
            let res = res?;
            if res.status() != StatusCode::OK {
                if let Some(connected_tx) = connected_tx {
                    connected_tx.send(true).unwrap();
                }
                return Ok(());
            }
            if post_connect {
                let mut stolen_connected_tx = None;
                std::mem::swap(&mut stolen_connected_tx, &mut connected_tx);
                tokio::spawn(Self::post_connect(_self.clone(), stolen_connected_tx));
            }
            Self::read_long_poll(_self.clone(), res).await;
        }
        Ok(())
    }

    async fn read_long_poll(_self: Arc<Mutex<Self>>, res: Response) {
        let mut bytes_stream = res.bytes_stream();
        let mut pending_message_bytes: Vec<u8> = vec![];
        let mut skip_count = 2;
        while let Some(Ok(chunk)) = bytes_stream.next().await {
            for byte in &chunk {
                if skip_count > 0 {
                    skip_count -= 1;
                    continue;
                }
                pending_message_bytes.push(*byte);
                // if let Ok(msg) = NewLongPollingPayload::parse_from_bytes(&pending_message_bytes) {
                //     println!("finished message: {}", base64::encode(pending_message_bytes));
                //     println!("got message: {msg:?}");
                //     pending_message_bytes = vec![];
                //     if let Some(data) = msg.data.as_ref() {
                //         let handle_res = Self::handle_rpc_message(_self.clone(), data.clone()).await;
                //         if handle_res.is_err() {
                //             println!("failed to handle message: {}", handle_res.unwrap_err());
                //         } else {
                //             println!("successfully handled message!");
                //         }
                //     }
                // }
                if let Err(_) = String::from_utf8(pending_message_bytes.clone()) {
                    log::error!("message is not text! (probably protobuf)");
                    pending_message_bytes = vec![];
                    continue;
                }
                let message_string = String::from_utf8(pending_message_bytes.clone()).unwrap();
                if message_string.len() < 2 {
                    continue;
                }
                // if !message_string.starts_with("[["){
                //     println!("message does not start with [[! beeper said it would! clearing");
                //     println!("clearing message {message_string}");
                //     pending_message_bytes = vec![];
                //     continue;
                // }
                // message_string = format!("{message_string}");
                if message_string.chars().filter(|c| *c == '[').count() == message_string.chars().filter(|c| *c == ']').count() {
                    trace!("payload should be done {message_string}");
                    skip_count = 1;
                    let mut payload = LongPollingPayload::default();
                    if let Err(e) = pblite_rust::deserialize::unmarshal(&message_string, &mut payload) {
                        warn!("failed to parse pblite message {e}");
                        pending_message_bytes = vec![];
                        continue
                    }
                    if payload.data.is_some() {
                        Self::handle_rpc_message(_self.clone(), *payload.data.0.unwrap()).await.unwrap();
                    }
                    pending_message_bytes = vec![];
                }
            }
        }
    }

    async fn handle_rpc_message(_self: Arc<Mutex<Self>>, raw_msg: IncomingRPCMessage) -> anyhow::Result<()> {
        _self.lock().await.ack_messages.push(raw_msg.responseID.clone());
        info!("got message! {}", raw_msg.bugleRoute.enum_value().map(|e| format!("{e:?}")).unwrap_or_default());
        if raw_msg.bugleRoute.enum_value_or_default() == BugleRoute::PairEvent {
            debug!("completing pairing {raw_msg}");
            let paired_data = RPCPairData::parse_from_bytes(&raw_msg.messageData).unwrap();
            if paired_data.has_paired() {
                Self::complete_pairing(_self.clone(), paired_data.paired().clone()).await;
            }
            if paired_data.has_revoked() {
                warn!("paired data revoked!!");
            }
        }
        if raw_msg.bugleRoute.value() == BugleRoute::DataEvent.value() {
            if let Ok(rpc_message) = RPCMessageData::parse_from_bytes(&raw_msg.messageData) {
                let msg = Self::decrypt_internal_message(_self.clone(), rpc_message.clone()).await.unwrap();
                debug!("received message: {} \n inner: {msg:?}", protobuf_json_mapping::print_to_string(&rpc_message).unwrap());
                info!("checking for pending message with id {}", &rpc_message.sessionID);
                if let Some(response_sender) = _self.lock().await.pending_messages.remove(&rpc_message.sessionID) {
                    response_sender.send(msg).unwrap();
                }
            } else {
                warn!("failed to parse rpc message");
            }
        }
        
        Ok(())
    }

    async fn complete_pairing(_self: Arc<Mutex<Self>>, data: PairedData) {
        _self.lock().await.update_tachyon_auth_token(*data.tokenData.0.unwrap());
        _self.lock().await.auth_data.mobile = *data.mobile.0.unwrap();
        _self.lock().await.auth_data.browser = *data.browser.0.unwrap();
        sleep(Duration::from_secs(2)).await;
        if let Some(pairing_tx) = std::mem::take(&mut _self.lock().await.pairing_complete) {
            pairing_tx.send(true).unwrap();
        }
        // Self::reconnect(_self).await;
    }

    // async fn reconnect(_self: Arc<Mutex<Self>>) -> anyhow::Result<()> {
    //     if let Some(conn_handle) = &_self.lock().await.conn_handle {
    //         conn_handle.abort();
    //         println!("killed connection!");
    //     }
    //     Self::connect(_self.clone()).await;
    //     Ok(())
    // }

    pub async fn connect(_self: Arc<Mutex<Self>>) -> anyhow::Result<bool> {
        _self.lock().await.refresh_auth_token().await?;
        // c.bumpNextDataReceiveCheck(10 * time.Minute);
        let (connected_tx, connected_rx) = oneshot::channel();
        tokio::spawn(Self::do_long_poll(_self.clone(), true, true, Some(connected_tx)));
        let ack_self = _self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if let Err(_) = Self::send_ack_request(ack_self.clone()).await {
                    warn!("send ack failed");
                }
            }
        });
        Ok(connected_rx.await?)
        // go c.doLongPoll(true, c.postConnect)
        // c.sessionHandler.startAckInterval()
    }

    async fn post_connect(_self: Arc<Mutex<Self>>, connected_tx: Option<oneshot::Sender<bool>>) {
        debug!("waiting two seconds for acks");
        sleep(Duration::from_secs(2)).await;
        let _ = Self::send_ack_request(_self.clone()).await;
        debug!("waiting one second for active session");
        sleep(Duration::from_secs(1)).await;
        Self::set_active_session(_self.clone()).await.unwrap();
        sleep(Duration::from_secs(2)).await;
        debug!("waited two seconds chill");
        let ActionMessage::IsBugleDefault(bugle_default) = Self::send_message(_self.clone(), ActionType::IS_BUGLE_DEFAULT, false, None::<&IsBugleDefaultResponse>, false, Uuid::new_v4().into(), None, None).await.unwrap() else { panic!() };
        debug!("bugle default: {}", bugle_default.success);
        if let Some(connected_tx) = connected_tx {
            connected_tx.send(true).unwrap();
        }
    }

    async fn set_active_session(_self: Arc<Mutex<Self>>) -> anyhow::Result<()> {
        let session_id = Uuid::new_v4().to_string();
        _self.lock().await.session_id = session_id.clone();
        Self::send_message_no_response(_self.clone(), ActionType::GET_UPDATES, true, None::<&AuthMessage /* doesn't matter */>, false, session_id, None, None).await
    }

    pub async fn send_message_no_response(_self: Arc<Mutex<Self>>, action: ActionType, omit_ttl: bool, data: Option<&impl Message>, dont_encrypt: bool, request_id: String, message_type: Option<MessageType>, custom_ttl: Option<i64>) -> anyhow::Result<()> {
        let payload = Self::build_message(_self.clone(), action, omit_ttl, data, dont_encrypt, request_id, message_type, custom_ttl).await.unwrap();
        debug!("payload: {}", protobuf_json_mapping::print_to_string(&payload).unwrap());
        let url = format!("{INSTANT_MESSAGING_BASE_URL}{MESSAGING_BASE_URL}{SEND_MESSAGE_URL}");
        let _: OutgoingRPCResponse = _self.lock().await.typed_api_call(url, &payload).await?;
        Ok(())
    }

    pub async fn send_message(_self: Arc<Mutex<Self>>, action: ActionType, omit_ttl: bool, data: Option<&impl Message>, dont_encrypt: bool, request_id: String, message_type: Option<MessageType>, custom_ttl: Option<i64>) -> anyhow::Result<ActionMessage> {
        let (response_tx, response_rx) = oneshot::channel();
        _self.lock().await.pending_messages.insert(request_id.clone(), response_tx);
        Self::send_message_no_response(_self, action, omit_ttl, data, dont_encrypt, request_id.clone(), message_type, custom_ttl).await?;
        info!("waiting for response with id: {request_id}");
        let response = response_rx.await;
        Ok(response?)
    }

    async fn send_ack_request(_self: Arc<Mutex<Self>>) -> anyhow::Result<()> {
        let device = _self.lock().await.auth_data.browser.clone();
        let ack_messages: Vec<_> = std::mem::take(&mut _self.lock().await.ack_messages).into_iter().map(|request_id| {
            ack_message_request::Message {
                requestID: request_id,
                device: MessageField::some(device.clone()),
                ..Default::default()
            }
        }).collect();
        let payload = AckMessageRequest {
            authData: MessageField::some(AuthMessage {
                requestID: Uuid::new_v4().to_string(),
                tachyonAuthToken: _self.lock().await.auth_data.tachyon_auth_token.clone(),
                network: "".into(),
                configVersion: MessageField::some(config_version()),
                ..Default::default()
            }),
            acks: ack_messages,
            ..Default::default()
        };
        let url = format!("{INSTANT_MESSAGING_BASE_URL}{MESSAGING_BASE_URL}{ACK_MESSAGES_URL}");
        let _: OutgoingRPCResponse = _self.lock().await.typed_api_call(url, &payload).await?;
        Ok(())
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
                configVersion: MessageField::some(config_version()),
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

    async fn build_message(_self: Arc<Mutex<Self>>, action: ActionType, omit_ttl: bool, data: Option<&impl Message>, dont_encrypt: bool, request_id: String, message_type: Option<MessageType>, custom_ttl: Option<i64>) -> anyhow::Result<OutgoingRPCMessage>{
        let _self = _self.lock().await;
        let session_id = _self.session_id.clone();
        let message_type = message_type.unwrap_or(MessageType::BUGLE_MESSAGE);
        let mut message = OutgoingRPCMessage {
            mobile: MessageField::some(_self.auth_data.mobile.clone()),
            data: MessageField::some(outgoing_rpcmessage::Data {
                requestID: request_id.clone(),
                bugleRoute: BugleRoute::DataEvent.into(),
                messageTypeData: MessageField::some(outgoing_rpcmessage::data::Type {
                    messageType: message_type.into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            auth: MessageField::some(outgoing_rpcmessage::Auth {
                requestID: request_id.clone(),
                tachyonAuthToken: _self.auth_data.tachyon_auth_token.clone(),
                configVersion: MessageField::some(config_version()),
                ..Default::default()
            }),
            ..Default::default()
        };
        //TODO: handle auth_data.dest_reg_id
        if let Some(custom_ttl) = custom_ttl {
            message.TTL = custom_ttl;
        } else if !omit_ttl {
            message.TTL = _self.auth_data.tachyon_ttl.as_secs() as i64;
        }
        let mut unencrypted_data = vec![];
        let mut encrypted_data = vec![];
        if data.is_some() {
            if dont_encrypt {
                unencrypted_data = data.unwrap().write_to_bytes()?;
            } else {
                encrypted_data = _self.auth_data.request_crypto.encrypt(data.unwrap().write_to_bytes()?);
            }
        }
        message.data.as_mut().unwrap().messageData = OutgoingRPCData {
            requestID: request_id.clone(),
            action: action.into(),
            unencryptedProtoData: unencrypted_data,
            encryptedProtoData: encrypted_data,
            sessionID: session_id,
            ..Default::default()
        }.write_to_bytes()?;

        Ok(message)
    }

    pub async fn decrypt_internal_message(_self: Arc<Mutex<Self>>, rpc_message: RPCMessageData) -> anyhow::Result<ActionMessage> {
        let decrypted_data = _self.lock().await.auth_data.request_crypto.decrypt(rpc_message.encryptedData);
        let action_message = parse_action_message(decrypted_data, rpc_message.action.enum_value_or_default()).unwrap();
        Ok(action_message)
    }
}

const UA_PLATFORM: &'static str = "Android";
const SEC_UA: &'static str = r#""Google Chrome";v="123", "Chromium";v="123", "Not-A.Brand";v="24""#;
const X_USER_AGENT: &'static str = "grpc-web-javascript/0.1";
const GOOGLE_API_KEY: &'static str = "AIzaSyCA4RsOZUFrm9whhtGosPlJLmVPnfSHKz8"; //from beeper
const SEC_UA_MOBILE: &'static str = "?1";

fn config_version() -> ConfigVersion {
    ConfigVersion {
        Year: 2024,
        Month: 12,
        Day: 9,
        V1: 4,
        V2: 6,
        ..Default::default()
    }
}

pub fn generate_tmp_id() -> String {
	let x = rand::random::<i64>() % 1000000000000;
	return format!("tmp_{x}");
}

pub enum ActionMessage {
    IsBugleDefault(IsBugleDefaultResponse),
    GetUpdates(UpdateEvents),
    ListConversations(ListConversationsResponse),
    NotifyDittoActivity(NotifyDittoActivityResponse),
    GetConversationType(GetConversationTypeResponse),
    GetConversation(GetConversationResponse),
    ListMessages(ListMessagesResponse),
    SendMessage(SendMessageResponse),
    SendReaction(SendReactionResponse),
    DeleteMessage(DeleteMessageResponse),
    GetParticipantsThumbnail(GetThumbnailResponse),
    GetContactsThumbnail(GetThumbnailResponse),
    ListContacts(ListContactsResponse),
    ListTopContacts(ListTopContactsResponse),
    GetOrCreateConversation(GetOrCreateConversationResponse),
    UpdateConversation(UpdateConversationResponse),
}

impl ActionMessage {
    pub fn message(&self) -> &dyn MessageDyn {
        match self {
            ActionMessage::DeleteMessage(m) => m,
            ActionMessage::IsBugleDefault(m) => m,
            ActionMessage::GetUpdates(m) => m,
            ActionMessage::ListConversations(m) => m,
            ActionMessage::NotifyDittoActivity(m) => m,
            ActionMessage::GetConversationType(m) => m,
            ActionMessage::GetConversation(m) => m,
            ActionMessage::ListMessages(m) => m,
            ActionMessage::SendMessage(m) => m,
            ActionMessage::SendReaction(m) => m,
            ActionMessage::GetParticipantsThumbnail(m) => m,
            ActionMessage::GetContactsThumbnail(m) => m,
            ActionMessage::ListContacts(m) => m,
            ActionMessage::ListTopContacts(m) => m,
            ActionMessage::GetOrCreateConversation(m) => m,
            ActionMessage::UpdateConversation(m) => m,
        }
    }
}

impl Debug for ActionMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message: &dyn MessageDyn = self.message();
        f.write_str(&protobuf_json_mapping::print_to_string(message).unwrap_or_default())
    }
}

pub fn parse_action_message(data: Vec<u8>, action_type: ActionType) -> anyhow::Result<ActionMessage> {
    Ok(match action_type {
        ActionType::IS_BUGLE_DEFAULT => ActionMessage::IsBugleDefault(IsBugleDefaultResponse::parse_from_bytes(&data)?),
        ActionType::GET_UPDATES => ActionMessage::GetUpdates(UpdateEvents::parse_from_bytes(&data)?),
        ActionType::LIST_CONVERSATIONS => ActionMessage::ListConversations(ListConversationsResponse::parse_from_bytes(&data)?),
        ActionType::NOTIFY_DITTO_ACTIVITY => ActionMessage::NotifyDittoActivity(NotifyDittoActivityResponse::parse_from_bytes(&data)?),
        ActionType::GET_CONVERSATION_TYPE => ActionMessage::GetConversationType(GetConversationTypeResponse::parse_from_bytes(&data)?),
        ActionType::GET_CONVERSATION => ActionMessage::GetConversation(GetConversationResponse::parse_from_bytes(&data)?),
        ActionType::LIST_MESSAGES => ActionMessage::ListMessages(ListMessagesResponse::parse_from_bytes(&data)?),
        ActionType::SEND_MESSAGE => ActionMessage::SendMessage(SendMessageResponse::parse_from_bytes(&data)?),
        ActionType::SEND_REACTION => ActionMessage::SendReaction(SendReactionResponse::parse_from_bytes(&data)?),
        ActionType::DELETE_MESSAGE => ActionMessage::DeleteMessage(DeleteMessageResponse::parse_from_bytes(&data)?),
        ActionType::GET_PARTICIPANTS_THUMBNAIL => ActionMessage::GetParticipantsThumbnail(GetThumbnailResponse::parse_from_bytes(&data)?),
        ActionType::GET_CONTACTS_THUMBNAIL => ActionMessage::GetContactsThumbnail(GetThumbnailResponse::parse_from_bytes(&data)?),
        ActionType::LIST_CONTACTS => ActionMessage::ListContacts(ListContactsResponse::parse_from_bytes(&data)?),
        ActionType::LIST_TOP_CONTACTS => ActionMessage::ListTopContacts(ListTopContactsResponse::parse_from_bytes(&data)?),
        ActionType::GET_OR_CREATE_CONVERSATION => ActionMessage::GetOrCreateConversation(GetOrCreateConversationResponse::parse_from_bytes(&data)?),
        ActionType::UPDATE_CONVERSATION => ActionMessage::UpdateConversation(UpdateConversationResponse::parse_from_bytes(&data)?),
        _ => todo!("wasn't in beepers implementation"),
    })
}