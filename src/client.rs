use core::panic;
use std::{collections::HashMap, sync::Arc, time::{Duration, SystemTime}};

use base64::Engine;
use jsonwebkey::JsonWebKey;
use log::{debug, info, trace, warn};
use protobuf::{Enum, EnumOrUnknown, Message, MessageField, MessageFull};
use reqwest::{header::HeaderMap, IntoUrl, Method, RequestBuilder, Response, StatusCode};
use ring::{digest::SHA256, rand::SystemRandom, signature::{self}};
use serde::{Deserialize, Serialize};
use tokio::{sync::{mpsc, oneshot::{self, Sender}, Mutex}, task::JoinHandle, time::sleep};
use uuid::Uuid;
use crate::{consts::UPLOAD_MEDIA_URL, crypto::{gcm_encrypt, generate_key}, messages::{Attachment, Conversation, Event, RegularMessage, TypingMessage}, protos::{authentication::{authentication_container, register_refresh_request::NestedEmptyArr, AuthenticationContainer, BrowserDetails, BrowserType, DeviceType, ECDSAKeys, KeyData, PairedData, RegisterRefreshRequest, RegisterRefreshResponse}, client::{ack_message_request, receive_messages_request::UnknownEmptyObject2, AckMessageRequest, IsBugleDefaultResponse, ReceiveMessagesRequest, StartMediaUploadRequest, UploadMediaResponse}, conversations::{self, MediaContent, MediaFormats, MessageStatusType}, events::{RPCPairData, TypingTypes, UpdateEvents}, rpc::{outgoing_rpcmessage, ActionType, BugleRoute, IncomingRPCMessage, LongPollingPayload, MessageType, OutgoingRPCData, OutgoingRPCMessage, OutgoingRPCResponse, RPCMessageData}}, util::{config_version, mime_to_media_type}};
use crate::{crypto::AESCTRHelper, protos::{authentication::{sign_in_gaia_request, AuthMessage, Device, RegisterPhoneRelayResponse, SignInGaiaRequest, SignInGaiaResponse, TokenData, URLData}, config::Config}};
use crate::consts::{REGISTER_REFRESH_URL, ACK_MESSAGES_URL, INSTANT_MESSAGING_BASE_URL, MESSAGING_BASE_URL, PAIRING_BASE_URL, QR_CODE_URL_BASE, QR_NETWORK, RECEIVE_MESSAGES_URL, REGISTER_PHONE_RELAY_URL, SEND_MESSAGE_URL, USER_AGENT, CONFIG_URL, GOOGLE_NETWORK, INSTANT_MESSAGING_BASE_URLGOOGLE, REGISTRATION_BASE_URL, SIGN_IN_GAIA_URL};
use futures_util::StreamExt;

#[derive(Serialize, Deserialize)]
pub struct Client {
    pub auth_data: AuthData,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub http_client: reqwest::Client,
    #[serde(serialize_with = "crate::serializers::serialize_proto", deserialize_with = "crate::serializers::deserialize_proto")]
    pub config: Config,

    pub listen_id: i32,
    #[serde(skip_serializing, skip_deserializing, default = "return_none")]
    pub conn_handle: Option<JoinHandle<anyhow::Result<()>>>,
    pub ack_messages: Vec<String>,
    pub session_id: String,

    #[serde(skip_serializing, skip_deserializing, default = "return_none")]
    pub pairing_complete: Option<Sender<bool>>,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub pending_messages: HashMap<String, oneshot::Sender<Vec<u8>>>,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub seen_message_ids: HashMap<String, conversations::Message>,
    #[serde(skip_serializing, skip_deserializing, default = "new_message_channel")]
    pub message_channel: (Arc<Mutex<mpsc::Receiver<Event>>>, mpsc::Sender<Event>),
}

fn new_message_channel() -> (Arc<Mutex<mpsc::Receiver<Event>>>, mpsc::Sender<Event>) {
    let (tx, rx) = mpsc::channel(128);
    (Arc::new(Mutex::new(rx)), tx)
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
    #[serde(serialize_with = "crate::serializers::serialize_proto", deserialize_with = "crate::serializers::deserialize_proto")]
    pub mobile: Device,
    #[serde(serialize_with = "crate::serializers::serialize_proto", deserialize_with = "crate::serializers::deserialize_proto")]
    pub browser: Device,
}

#[allow(unused)]
pub struct PrimaryDeviceID {
	reg_id: String,
	unknown_int: u64,
}

impl Client {
    pub async fn new() -> Self {
        let message_channel = new_message_channel();
        let mut _self = Self {
            auth_data: AuthData {
                request_crypto: AESCTRHelper::new(), 
                session_id: Uuid::default(),
                refresh_key: JsonWebKey::new(jsonwebkey::Key::generate_p256()),
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
            seen_message_ids: HashMap::new(),
            message_channel,
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

    #[allow(unused)]
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
        let payload = AuthenticationContainer {
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
            AESKey: self.auth_data.request_crypto.aes_key.clone(),
            HMACKey: self.auth_data.request_crypto.hmac_key.clone(),
            ..Default::default()
        };
        let c_data = base64::engine::general_purpose::STANDARD.encode(url_data.write_to_bytes().unwrap());
        return format!("{QR_CODE_URL_BASE}{c_data}");
    }

    async fn do_long_poll(_self: Arc<Mutex<Self>>, logged_in: bool, post_connect: bool, mut connected_tx: Option<oneshot::Sender<bool>>) -> anyhow::Result<()>{
        _self.lock().await.listen_id += 1;
        let listen_id = _self.lock().await.listen_id.clone();
        let listen_req_id = Uuid::new_v4().to_string();
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
                    warn!("failed to connect to the server!");
                    connected_tx.send(false).unwrap();
                }
                return Ok(());
            }
            let res = res?;
            if res.status() != StatusCode::OK {
                if let Some(connected_tx) = connected_tx {
                    warn!("the server responded with a non-ok status code! {}", res.status());
                    connected_tx.send(false).unwrap();
                }
                return Ok(());
            }
            info!("connected to the server!");
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

                if let Err(_) = String::from_utf8(pending_message_bytes.clone()) {
                    log::error!("message is not text! (probably protobuf)");
                    pending_message_bytes = vec![];
                    continue;
                }
                let message_string = String::from_utf8(pending_message_bytes.clone()).unwrap();
                if message_string.len() < 2 {
                    continue;
                }

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
                let msg_bytes = Self::decrypt_internal_message(_self.clone(), rpc_message.clone()).await.unwrap();
                trace!("received message: {}", protobuf_json_mapping::print_to_string(&rpc_message).unwrap());
                if let Some(response_sender) = _self.lock().await.pending_messages.remove(&rpc_message.sessionID) {
                    response_sender.send(msg_bytes.clone()).unwrap();
                }
                let message_tx = _self.lock().await.message_channel.1.clone();
                tokio::spawn(async move {
                    if rpc_message.action.value() == ActionType::GET_UPDATES.value() {
                        if let Ok(event) = UpdateEvents::parse_from_bytes(&msg_bytes) {
                            trace!("inner: {}", protobuf_json_mapping::print_to_string(&event).unwrap());
                            if event.has_messageEvent() {
                                let message_event = event.messageEvent();
                                for message in message_event.data.clone() {
                                    if let Some(message_status) = message.messageStatus.as_ref() {
                                        if let Ok(status_val) = message_status.status.enum_value() {
                                            if status_val == MessageStatusType::INCOMING_COMPLETE {
                                                if _self.lock().await.seen_message_ids.get(&message.messageID) != Some(&message) {
                                                    _self.lock().await.seen_message_ids.insert(message.messageID.clone(), message.clone());
                                                    debug!("{}: {:?}", &message.messageID, status_val);
                                                    trace!("{}", protobuf_json_mapping::print_to_string(&message).unwrap());
                                                    let parsed_message = RegularMessage::from_proto(_self.clone(), message, true, true).await;
                                                    message_tx.send(Event::Message(parsed_message)).await.unwrap();
                                                }
                                            } else {
                                                debug!("{}: {:?}", &message.messageID, status_val);
                                                trace!("{message:?}");
                                            }
                                        }
                                    }
                                }
                            }
                            if event.has_typingEvent() {
                                let typing_event = event.typingEvent();
                                let typing_message = TypingMessage {
                                    conversation_id: typing_event.data.conversationID.clone(),
                                    typing: typing_event.data.type_.value() == TypingTypes::STARTED_TYPING.value(),
                                    sender_number: typing_event.data.user.number.clone(),
                                };
                                message_tx.send(Event::Typing(typing_message)).await.unwrap();
                            }
                            if event.has_conversationEvent() {
                                let conversation_event = event.conversationEvent();
                                for proto_conversation in &conversation_event.data {
                                    let conversation = Conversation {
                                        group_name: if proto_conversation.isGroupChat { Some(proto_conversation.name.clone()) } else { None },
                                        participants: proto_conversation.otherParticipants.clone(),
                                    };
                                    message_tx.send(Event::ConversationUpdate(conversation)).await.unwrap();
                                }
                            }
                        }
                    }
                });
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
    }

    pub async fn connect(_self: Arc<Mutex<Self>>) -> anyhow::Result<bool> {
        _self.lock().await.refresh_auth_token().await?;
        let (connected_tx, connected_rx) = oneshot::channel();
        tokio::spawn(Self::do_long_poll(_self.clone(), true, true, Some(connected_tx)));
        let ack_self = _self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Err(_) = Self::send_ack_request(ack_self.clone()).await {
                    warn!("send ack failed");
                }
            }
        });
        Ok(connected_rx.await?)
    }

    pub async fn receive_message(_self: Arc<Mutex<Self>>) -> Option<Event> {
        let rx_mutex = _self.lock().await.message_channel.0.clone();
        let mut rx = rx_mutex.lock().await;
        rx.recv().await
    }

    async fn post_connect(_self: Arc<Mutex<Self>>, connected_tx: Option<oneshot::Sender<bool>>) {
        let _ = Self::send_ack_request(_self.clone()).await;
        Self::set_active_session(_self.clone()).await.unwrap();
        let bugle_default: IsBugleDefaultResponse = Self::send_message_typed(_self.clone(), ActionType::IS_BUGLE_DEFAULT, false, None::<&IsBugleDefaultResponse>, false, Uuid::new_v4().into(), None, None).await.unwrap();
        trace!("bugle default: {}", bugle_default.success);
        if let Some(connected_tx) = connected_tx {
            info!("ready to send");
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
        trace!("payload: {}", protobuf_json_mapping::print_to_string(&payload).unwrap());
        let url = format!("{INSTANT_MESSAGING_BASE_URL}{MESSAGING_BASE_URL}{SEND_MESSAGE_URL}");
        let _: OutgoingRPCResponse = _self.lock().await.typed_api_call(url, &payload).await?;
        Ok(())
    }

    pub async fn send_message(_self: Arc<Mutex<Self>>, action: ActionType, omit_ttl: bool, data: Option<&impl Message>, dont_encrypt: bool, request_id: String, message_type: Option<MessageType>, custom_ttl: Option<i64>) -> anyhow::Result<Vec<u8>> {
        let (response_tx, response_rx) = oneshot::channel();
        _self.lock().await.pending_messages.insert(request_id.clone(), response_tx);
        Self::send_message_no_response(_self, action, omit_ttl, data, dont_encrypt, request_id.clone(), message_type, custom_ttl).await?;
        let response = response_rx.await;
        Ok(response?)
    }

    pub async fn send_message_typed<M: MessageFull>(_self: Arc<Mutex<Self>>, action: ActionType, omit_ttl: bool, data: Option<&impl Message>, dont_encrypt: bool, request_id: String, message_type: Option<MessageType>, custom_ttl: Option<i64>) -> anyhow::Result<M> {
        let response = Self::send_message(_self, action, omit_ttl, data, dont_encrypt, request_id, message_type, custom_ttl).await?;
        Ok(M::parse_from_bytes(&response)?)
    }

    #[allow(unused)]
    pub async fn send_basic_message(_self: Arc<Mutex<Self>>, action: ActionType, data: Option<&impl Message>) -> anyhow::Result<Vec<u8>> {
        Self::send_message(_self, action, false, data, false, Uuid::new_v4().into(), None, None).await
    }

    pub async fn send_basic_message_typed<M: MessageFull>(_self: Arc<Mutex<Self>>, action: ActionType, data: Option<&impl Message>) -> anyhow::Result<M> {
        Self::send_message_typed::<M>(_self, action, false, data, false, Uuid::new_v4().into(), None, None).await
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
        if ack_messages.is_empty() {
            return Ok(())
        }
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

    pub async fn decrypt_internal_message(_self: Arc<Mutex<Self>>, rpc_message: RPCMessageData) -> anyhow::Result<Vec<u8>> {
        let decrypted_data = _self.lock().await.auth_data.request_crypto.decrypt(rpc_message.encryptedData);
        // let action_message = parse_action_message(decrypted_data, rpc_message.action.enum_value_or_default()).unwrap();
        Ok(decrypted_data)
    }

    pub async fn upload_media(_self: Arc<Mutex<Self>>, attachment: &Attachment) -> MediaContent {
        let key = generate_key(32);
        let encrypted_bytes = gcm_encrypt(&key, attachment.data.clone());

        let headers = Self::build_media_update_headers(encrypted_bytes.len().to_string(), "start".into(), "".into(), attachment.mime_type.clone(), "resumable".into());
        let c = _self.lock().await;
        let start_req = StartMediaUploadRequest {
            attachmentType: 1,
            authData: MessageField::some(AuthMessage {
                requestID:        Uuid::new_v4().into(),
                tachyonAuthToken: c.auth_data.tachyon_auth_token.clone(),
                network:          "".into(),
                configVersion:    MessageField::some(config_version()),
                ..Default::default()
            }),
            mobile: MessageField::some(c.auth_data.mobile.clone()),
            ..Default::default()
        };
    
        let req_body = base64::engine::general_purpose::STANDARD.encode(start_req.write_to_bytes().unwrap());

        let req = c.http_client.post(format!("{INSTANT_MESSAGING_BASE_URL}{UPLOAD_MEDIA_URL}")).headers(headers).body(req_body);
        let res = c.http_client.execute(req.build().unwrap()).await.unwrap();
        res.error_for_status_ref().unwrap();

        let upload_url = res.headers().get("x-goog-upload-url").unwrap().to_str().unwrap();

        let finalize_headers = Self::build_media_update_headers(encrypted_bytes.len().to_string(), "upload, finalize".into(), "0".into(), attachment.mime_type.clone(), "".into());
        let req = c.http_client.post(upload_url).body(encrypted_bytes).headers(finalize_headers);
        let res = c.http_client.execute(req.build().unwrap()).await.unwrap();
        res.error_for_status_ref().unwrap();
        let response_body = res.bytes().await.unwrap().to_vec();
        let mut media_ids = UploadMediaResponse::default();

        if let Ok(Ok(base64_bytes)) = String::from_utf8(response_body.clone()).map(|it| base64::engine::general_purpose::STANDARD.decode(it)) {
            media_ids = UploadMediaResponse::parse_from_bytes(&base64_bytes).unwrap();
        } else {
            let pblite_res = String::from_utf8(response_body).unwrap();
            pblite_rust::deserialize::unmarshal(&pblite_res, &mut media_ids).unwrap();
        }

        let (ext, format) = match mime_to_media_type(&attachment.mime_type).map(|it| Some(it)).unwrap_or(mime_to_media_type(&attachment.mime_type.split("/").next().unwrap_or(""))) {
            Some((ext, format)) => (format!(".{ext}"), format.into()),
            None => ("".into(), EnumOrUnknown::new(MediaFormats::UNSPECIFIED_TYPE)),
        };

        MediaContent {
            format,
            mediaID: media_ids.media.mediaID.clone(),
            mediaName: attachment.file_name.clone().unwrap_or(format!("{}{ext}", Uuid::new_v4().to_string())),
            size: attachment.data.len() as i64,
            decryptionKey: key.clone(),
            mimeType: attachment.mime_type.clone(),
            ..Default::default()
        }
    }

    fn build_media_update_headers(image_size: String, command: String, upload_offset: String, image_content_type: String, protocol: String) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("sec-ch-ua", SEC_UA.parse().unwrap());
        if protocol != "" {
            headers.insert("x-goog-upload-protocol", protocol.parse().unwrap());
        }
        headers.insert("x-goog-upload-header-content-length", image_size.parse().unwrap());
        headers.insert("sec-ch-ua-mobile", SEC_UA_MOBILE.parse().unwrap());
        headers.insert("user-agent", USER_AGENT.parse().unwrap());
        if image_content_type != "" {
            headers.insert("x-goog-upload-header-content-type", image_content_type.parse().unwrap());
        }
        headers.insert("content-type", "application/x-www-form-urlencoded;charset=UTF-8".parse().unwrap());
        if command != "" {
            headers.insert("x-goog-upload-command", command.parse().unwrap());
        }
        if upload_offset != "" {
            headers.insert("x-goog-upload-offset", upload_offset.parse().unwrap());
        }
        headers.insert("sec-ch-ua-platform", format!("\"{UA_PLATFORM}\"").parse().unwrap());
        headers.insert("accept", "*/*".parse().unwrap());
        headers.insert("origin", "https://messages.google.com".parse().unwrap());
        headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
        headers.insert("sec-fetch-mode", "cors".parse().unwrap());
        headers.insert("sec-fetch-dest", "empty".parse().unwrap());
        headers.insert("referer", "https://messages.google.com/".parse().unwrap());
        headers.insert("accept-encoding", "gzip, deflate, br".parse().unwrap());
        headers.insert("accept-language", "en-US,en;q=0.9".parse().unwrap());
        headers
    }
}

const UA_PLATFORM: &'static str = "Android";
const SEC_UA: &'static str = r#""Google Chrome";v="123", "Chromium";v="123", "Not-A.Brand";v="24""#;
const X_USER_AGENT: &'static str = "grpc-web-javascript/0.1";
const GOOGLE_API_KEY: &'static str = "AIzaSyCA4RsOZUFrm9whhtGosPlJLmVPnfSHKz8"; //from beeper
const SEC_UA_MOBILE: &'static str = "?1";

pub fn upload_headers(req_body: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
	//headers.insert("host", "instantmessaging-pa.googleapis.com".parse().unwrap())
	headers.insert("x-goog-download-metadata", req_body.parse().unwrap());
	headers.insert("sec-ch-ua", SEC_UA.parse().unwrap());
	headers.insert("sec-ch-ua-mobile", SEC_UA_MOBILE.parse().unwrap());
	headers.insert("user-agent", USER_AGENT.parse().unwrap());
	headers.insert("sec-ch-ua-platform", format!("\"{UA_PLATFORM}\"").parse().unwrap());
	headers.insert("accept", "*/*".parse().unwrap());
	headers.insert("origin", "https://messages.google.com".parse().unwrap());
	headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
	headers.insert("sec-fetch-mode", "cors".parse().unwrap());
	headers.insert("sec-fetch-dest", "empty".parse().unwrap());
	headers.insert("referer", "https://messages.google.com/".parse().unwrap());
	headers.insert("accept-encoding", "gzip, deflate, br".parse().unwrap());
	headers.insert("accept-language", "en-US,en;q=0.9".parse().unwrap());

    headers
}