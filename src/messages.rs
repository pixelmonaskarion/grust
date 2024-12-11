use std::sync::Arc;

use protobuf::MessageField;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{client::{generate_tmp_id, ActionMessage, Client}, protos::{client::{GetConversationRequest, GetOrCreateConversationRequest, MessagePayload, MessagePayloadContent, SendMessageRequest}, conversations::{self, ContactNumber, MessageContent, MessageInfo}, rpc::ActionType, settings::SIMPayload}};

#[derive(Debug, Clone)]
pub struct RegularMessage {
    pub text: String,
    pub conversation: ConversationOrId,
}

impl RegularMessage {
    pub async fn to_proto(&self, client: Arc<Mutex<Client>>) -> SendMessageRequest {
        let (conversation_id, my_id) = match self.conversation.clone() {
            ConversationOrId::Conversation(conversation) => {
                let conversation_res_outer = Client::send_message(client.clone(), ActionType::GET_OR_CREATE_CONVERSATION, false, Some(&GetOrCreateConversationRequest {
                    numbers: conversation.participants.iter().map(|participant| {
                        ContactNumber {
                            mysteriousInt: 2,
                            number: participant.clone(),
                            number2: participant.clone(),
                            ..Default::default()
                        }
                    }).collect(),
                    RCSGroupName: conversation.group_name,
                    createRCSGroup: Some(true),
                    ..Default::default()
                }), false, Uuid::new_v4().to_string(), None, None).await.unwrap();
                let ActionMessage::GetOrCreateConversation(conversation_res) = conversation_res_outer else { panic!() };
                (conversation_res.conversation.conversationID.clone(), conversation_res.conversation.defaultOutgoingID.clone())
            },
            ConversationOrId::ConversationId(id) => {
                let res_outer = Client::send_message(client.clone(), ActionType::GET_CONVERSATION, false, Some(&GetConversationRequest {
                    conversationID: id.clone(),
                    ..Default::default()
                }), false, Uuid::new_v4().into(), None, None).await.unwrap();
                let ActionMessage::GetConversation(conversation_res) = res_outer else { panic!() };
                (conversation_res.conversation.conversationID.clone(), conversation_res.conversation.defaultOutgoingID.clone())
            },
        };

        let tmp_id = generate_tmp_id();
        SendMessageRequest {
            conversationID: conversation_id.clone(),
            tmpID: tmp_id.clone(),
            SIMPayload: MessageField::some(SIMPayload {
                SIMNumber: 1,
                two: 2,
                ..Default::default()
            }),
            messagePayload: MessageField::some(MessagePayload {
                tmpID: tmp_id.clone(),
                tmpID2: tmp_id.clone(),
                conversationID: conversation_id.clone(),
                participantID: my_id.clone(),
                messagePayloadContent: MessageField::some(MessagePayloadContent {
                    messageContent: MessageField::some(MessageContent {
                        content: self.text.clone(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                messageInfo: vec![MessageInfo {
                    data: Some(conversations::message_info::Data::MessageContent(MessageContent {
                        content: self.text.clone(),
                        ..Default::default()
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
#[allow(unused)]
pub enum ConversationOrId {
    Conversation(Conversation),
    ConversationId(String),
}

#[derive(Debug, Clone)]
pub struct Conversation {
    pub participants: Vec<String>,
    pub group_name: Option<String>,
}