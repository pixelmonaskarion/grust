use std::{io, sync::Arc};

use client::Client;
use image::Luma;
use log::{debug, info, warn};
use messages::{Conversation, Event, MessagePart, RegularMessage};
use protos::rpc::ActionType;
use serde::Serialize;
use text_io::read;
use tokio::{fs, sync::{oneshot, Mutex}};
use uuid::Uuid;

mod consts;
mod protos;
mod client;
mod crypto;
mod messages;
mod serializers;
mod util;

#[tokio::main]
async fn main() {
    env_logger::init();
    let client: Arc<Mutex<Client>> = if let Ok(Ok(client)) = fs::read_to_string("client.json").await.map(|client_json| serde_json::from_str(&client_json).map_err(|e| { println!("{e:?}"); e })).map_err(|e| { println!("{e:?}"); e }) {
        Arc::new(Mutex::new(client))
    } else {
        info!("starting pairing!");
        let mut client = Client::new().await;
        let (pair_tx, pair_rx) = oneshot::channel();
        client.pairing_complete = Some(pair_tx);
        let client = Arc::new(Mutex::new(client));
        let qr_data = Client::start_login(client.clone()).await;
        let qrcode = qrcode::QrCode::new(qr_data.as_bytes()).unwrap();
        qrcode.render::<Luma<u8>>().build().save("qrcode.png").unwrap();
        info!("please scan the qr code!");
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
    let send_to = "4804550571".to_string();
    let client_clone = client.clone();
    tokio::spawn(async move {
        loop {
            if let Some(event) = Client::receive_message(client_clone.clone()).await {
                info!("{event}");
            }
        }
    });

    loop {
        let message: String = read!("{}\n");
        let message = RegularMessage {
            parts: vec![
                MessagePart::Text(message),
            ],
            conversation: messages::ConversationOrId::Conversation(Conversation {
                participants: vec![send_to.clone()],
                group_name: None,
            }),
            // reply_messsage_id: Some("50812".into()),
            reply_messsage_id: None,
            sender: None,
            reactions: vec![],
        };
        let send_req = message.to_proto(client.clone()).await;
        Client::send_message(client.clone(), ActionType::SEND_MESSAGE, false, Some(&send_req), false, Uuid::new_v4().to_string(), None, None).await.unwrap();
    }
}

pub struct ClientMutex {
    client: Arc<Mutex<Client>>,
}

impl ClientMutex {
    pub async fn new() -> Self {
        Self {
            client: Arc::new(Mutex::new(Client::new().await)),
        }
    }

    pub async fn from_file(path: &str) -> Result<Self, io::Error> {
        let client = fs::read_to_string(path).await.map(|client_json| serde_json::from_str(&client_json).map_err(|e| { warn!("{e:?}"); e }))??;
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
        })
    }

    pub async fn start_login(&self) -> String {
        Client::start_login(self.client.clone()).await
    }

    pub async fn connect(&self) -> anyhow::Result<bool> {
        Client::connect(self.client.clone()).await
    }

    pub async fn receive_message(&self) -> Option<Event> {
        let rx_mutex = self.client.lock().await.message_channel.0.clone();
        let mut rx = rx_mutex.lock().await;
        rx.recv().await
    }
}