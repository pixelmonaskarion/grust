use std::{fmt::Formatter, marker::PhantomData, sync::Arc};

use client::{generate_tmp_id, ActionMessage, Client};
use image::Luma;
use log::{debug, info};
use protobuf::{MessageDyn, MessageField, MessageFull};
use protos::{client::{GetOrCreateConversationRequest, MessagePayload, MessagePayloadContent, SendMessageRequest}, conversations::{self, ContactNumber, MessageContent, MessageInfo}, rpc::ActionType, settings::SIMPayload};
use serde::Serialize;
use tokio::{fs, sync::{oneshot, Mutex}};
use uuid::Uuid;

mod consts;
mod protos;
mod client;
mod crypto;
mod google_oauth;
mod browser;

#[tokio::main]
async fn main() {
    env_logger::init();
    let client: Arc<Mutex<Client>> = if let Ok(Ok(client)) = fs::read_to_string("client.json").await.map(|client_json| serde_json::from_str(&client_json)) {
        Arc::new(Mutex::new(client))
    } else {
        let mut client = Client::new().await;
        let (pair_tx, pair_rx) = oneshot::channel();
        client.pairing_complete = Some(pair_tx);
        let client = Arc::new(Mutex::new(client));
        let qr_data = Client::start_login(client.clone()).await;
        let qrcode = qrcode::QrCode::new(qr_data.as_bytes()).unwrap();
        qrcode.render::<Luma<u8>>().build().save("qrcode.png").unwrap();
        let pair_succeded = pair_rx.await.unwrap_or(false);
        if !pair_succeded {
            panic!("pairing failed! :(");
        }
        info!("pairing succeeded!");
        let mut writer = Vec::with_capacity(128);
        let mut serializer = serde_json::Serializer::new(&mut writer);
        client.lock().await.serialize(&mut serializer).unwrap();
        fs::write("client.json", writer).await.unwrap();
        client
    };
    
    debug!("connecting...");
    Client::connect(client.clone()).await.unwrap();

    info!("sending message");
    let conversation_res_outer = Client::send_message(client.clone(), ActionType::GET_OR_CREATE_CONVERSATION, false, Some(&GetOrCreateConversationRequest {
        numbers: vec![ContactNumber {
            mysteriousInt: 2,
            number: "+14804155320".into(),
            number2: "+14804155320".into(),
            ..Default::default()
        }],
        ..Default::default()
    }), false, Uuid::new_v4().to_string(), None, None).await.unwrap();
    info!("sent first req");
    info!("got conversation! {conversation_res_outer:?}");
    let ActionMessage::GetOrCreateConversation(conversation_res) = conversation_res_outer else { panic!() };
    let tmp_id = generate_tmp_id();
    let send_req = SendMessageRequest {
        conversationID: conversation_res.conversation.conversationID.clone(),
        tmpID: tmp_id.clone(),
        SIMPayload: MessageField::some(SIMPayload {
            SIMNumber: 1,
            two: 2,
            ..Default::default()
        }),
        messagePayload: MessageField::some(MessagePayload {
            tmpID: tmp_id.clone(),
            tmpID2: tmp_id.clone(),
            conversationID: conversation_res.conversation.conversationID.clone(),
            participantID: conversation_res.conversation.defaultOutgoingID.clone(),
            messagePayloadContent: MessageField::some(MessagePayloadContent {
                messageContent: MessageField::some(MessageContent {
                    content: "Hello World!".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            messageInfo: vec![MessageInfo {
                data: Some(conversations::message_info::Data::MessageContent(MessageContent {
                    content: "Hello World!".into(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    info!("sending! {}", protobuf_json_mapping::print_to_string(&send_req).unwrap());
    Client::send_message(client, ActionType::SEND_MESSAGE, false, Some(&send_req), false, Uuid::new_v4().to_string(), None, None).await.unwrap();
    loop {}
    // let _ = client.lock().await.conn_handle.take().unwrap().await;
}

fn serialize_proto<S: serde::Serializer>(
    m: &dyn MessageDyn,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&protobuf_json_mapping::print_to_string(m).map_err(|_| serde::ser::Error::custom("protobuf json serde failed"))?)
}

fn deserialize_proto<'de, E: MessageFull, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<E, D::Error> {
    struct DeserializeEnumVisitor<E: MessageFull>(PhantomData<E>);

    impl<'de, E: MessageFull> serde::de::Visitor<'de> for DeserializeEnumVisitor<E> {
        type Value = E;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            write!(formatter, "a json string representing the corrent protobuf type")
        }

        fn visit_str<R>(self, v: &str) -> Result<Self::Value, R>
        where
            R: serde::de::Error,
        {
            return protobuf_json_mapping::parse_from_str(v).map_err(|_| serde::de::Error::custom(format!("failed to parse json string {v}")))
        }
    }

    d.deserialize_any(DeserializeEnumVisitor(PhantomData))
}