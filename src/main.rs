use std::sync::Arc;

use client::Client;
use image::Luma;
use log::{debug, info};
use messages::{Conversation, RegularMessage};
use protos::rpc::ActionType;
use serde::Serialize;
use tokio::{fs, sync::{oneshot, Mutex}};
use uuid::Uuid;

mod consts;
mod protos;
mod client;
mod crypto;
// mod google_oauth;
mod messages;
mod serializers;

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
    let message = RegularMessage {
        text: "freak".into(),
        conversation: messages::ConversationOrId::Conversation(Conversation {
            participants: vec!["+14804550571".into()],
            group_name: None,
        }),
    };
    let send_req = message.to_proto(client.clone()).await;
    Client::send_message(client, ActionType::SEND_MESSAGE, false, Some(&send_req), false, Uuid::new_v4().to_string(), None, None).await.unwrap();
    info!("sent!");
    loop {}
    // let _ = client.lock().await.conn_handle.take().unwrap().await;
}