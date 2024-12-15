use std::{fmt::Display, sync::Arc};

use base64::Engine;
use protobuf::{Message as _, MessageField};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{client::{upload_headers, Client}, consts::{INSTANT_MESSAGING_BASE_URL, UPLOAD_MEDIA_URL}, crypto::gcm_decrypt, protos::{authentication::AuthMessage, client::{AttachmentInfo, DownloadAttachmentRequest, GetConversationRequest, GetConversationResponse, GetOrCreateConversationRequest, GetOrCreateConversationResponse, MessagePayload, ReplyPayload, SendMessageRequest}, conversations::{self, ContactNumber, MediaContent, MessageContent, MessageInfo}, rpc::ActionType, settings::SIMPayload}, util::{config_version, generate_tmp_id}};

pub enum Event {
    Message(RegularMessage),
    Typing(TypingMessage),
    ConversationUpdate(Conversation),
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(e) => e.fmt(f),
            Self::ConversationUpdate(e) => e.fmt(f),
            Self::Typing(e) => e.fmt(f),
        }
    }
}

pub struct TypingMessage {
    pub conversation_id: String,
    pub sender_number: String,
    pub typing: bool,
}

impl Display for TypingMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{} {} typing", self.sender_number, if self.typing { "is" } else { "stopped" }))
    }
}

#[derive(Debug, Clone)]
pub struct RegularMessage {
    pub parts: Vec<MessagePart>,
    pub conversation: ConversationOrId,
    pub reply_messsage_id: Option<String>, //outer message id, messageEvent.data.messageID, NOT messageInfo.actionMessageID (don't know what that is)
    pub sender: Option<String>,
    pub reactions: Vec<Reaction>,
}

impl RegularMessage {
    pub async fn to_proto(&self, client: Arc<Mutex<Client>>) -> SendMessageRequest {
        let (conversation_id, my_id) = match self.conversation.clone() {
            ConversationOrId::Conversation(conversation) => {
                let conversation_res: GetOrCreateConversationResponse = Client::send_basic_message_typed(client.clone(), ActionType::GET_OR_CREATE_CONVERSATION, Some(&GetOrCreateConversationRequest {
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
                })).await.unwrap();
                (conversation_res.conversation.conversationID.clone(), conversation_res.conversation.defaultOutgoingID.clone())
            },
            ConversationOrId::ConversationId(id) => {
                (id.clone(), todo!("get this from the config sent from the phone") as String)
            },
        };
        let sim_payload = SIMPayload { //TODO
            SIMNumber: 1,
            two: 2,
            ..Default::default()
        };
        let tmp_id = generate_tmp_id();
        let mut uploaded_parts = vec![];
        for part in &self.parts {
            uploaded_parts.push(match &part {
                MessagePart::Attachment(attachment) => {
                    let uploaded = Client::upload_media(client.clone(), attachment).await;
                    MessagePart::ServerMedia(uploaded)
                },
                _ => part.clone(),
            });
        }
        let message_info = uploaded_parts.iter().map(|part| {
            match part {
                MessagePart::Text(text) => {
                    MessageInfo {
                        data: Some(conversations::message_info::Data::MessageContent(MessageContent {
                            content: text.clone(),
                            ..Default::default()
                        })),
                        ..Default::default()
                    }
                },
                MessagePart::Attachment(_) => { panic!("upload should have been earlier") },
                MessagePart::ServerMedia(media) => {
                    MessageInfo {
                        data: Some(conversations::message_info::Data::MediaContent(media.clone())),
                        ..Default::default()
                    }
                }
            }
        }).collect();
        SendMessageRequest {
            conversationID: conversation_id.clone(),
            tmpID: tmp_id.clone(),
            SIMPayload: MessageField::some(sim_payload),
            messagePayload: MessageField::some(MessagePayload {
                tmpID: tmp_id.clone(),
                tmpID2: tmp_id.clone(),
                conversationID: conversation_id.clone(),
                participantID: my_id.clone(),
                messageInfo: message_info,
                ..Default::default()
            }),
            reply: self.reply_messsage_id.clone().map(|id| {
                MessageField::some(ReplyPayload {
                    messageID: id,
                    ..Default::default()
                })
            }).unwrap_or(MessageField::none()),
            ..Default::default()
        }
    }

    pub async fn from_proto(client: Arc<Mutex<Client>>, incoming_message: conversations::Message, resolve_conversation: bool, resolve_media: bool) -> RegularMessage {
        let mut conversation_participants = None;
        let conversation = if resolve_conversation {
            let conversation_res = super::messages::resolve_conversation(client.clone(), incoming_message.conversationID.clone()).await;
            conversation_participants = Some(conversation_res.conversation.participants.clone());
            let conversation = Conversation {
                participants: conversation_res.conversation.otherParticipants.clone(),
                group_name: if conversation_res.conversation.isGroupChat { Some(conversation_res.conversation.name.clone()) } else { None },
            };
            ConversationOrId::Conversation(conversation)
        } else {
            ConversationOrId::ConversationId(incoming_message.conversationID)
        };
        let mut parts = vec![];
        for part in incoming_message.messageInfo {
            if let Some(data) = part.data {
                let part = match data {
                    conversations::message_info::Data::MediaContent(media) => {
                        if resolve_media {
                            MessagePart::Attachment(super::messages::resolve_media(client.clone(), media).await)
                        } else {
                            MessagePart::ServerMedia(media)
                        }
                    },
                    conversations::message_info::Data::MessageContent(text_message) => {
                        MessagePart::Text(text_message.content)
                    }
                };
                parts.push(part);
            }
        }
        let reactions = incoming_message.reactions.iter().map(|reaction| {
            reaction.participantIDs.iter().map(|participant| {
                Reaction {
                    unicode: reaction.data.unicode.clone(),
                    participant_id: participant.clone(),
                }
            }).collect::<Vec<Reaction>>()
        }).collect::<Vec<Vec<Reaction>>>().concat();
        Self {
            reply_messsage_id: incoming_message.replyMessage.into_option().map(|it| it.messageID),
            parts,
            sender: match &conversation {
                ConversationOrId::Conversation(_) => {
                    let mut sender = None;
                    if let Some(conversation_participants) = conversation_participants {
                        for participant in conversation_participants {
                            if participant.ID.participantID == incoming_message.participantID {
                                sender = Some(participant.formattedNumber);
                                break;
                            }
                        }
                    }
                    sender
                },
                ConversationOrId::ConversationId(_) => Some(incoming_message.participantID.clone())
            },
            conversation,
            reactions,
        }
    }
}

impl Display for RegularMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts_formatted: String = self.parts.iter().map(|part| {
            let part_string = match part {
                MessagePart::Text(text) => text.clone(),
                MessagePart::Attachment(_) | MessagePart::ServerMedia(_) => "[Image]".into(),
            };
            format!("{part_string} ")
        }).collect();
        f.write_str(&format!("{}: {parts_formatted}", self.sender.clone().unwrap_or("[unknown]".into())))
    }
}

#[derive(Debug, Clone)]
pub struct Reaction {
    unicode: String,
    participant_id: String,
}

#[derive(Debug, Clone)]
#[allow(unused)]
pub enum MessagePart {
    Text(String),
    Attachment(Attachment),
    ServerMedia(MediaContent),
}

#[derive(Debug, Clone)]
pub struct Attachment {
    pub data: Vec<u8>,
    pub mime_type: String,
    pub file_name: Option<String>,
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

impl Display for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{}[{}]", self.group_name.as_ref().map(|it| format!("{it} ")).unwrap_or("".into()), self.participants.join(", ")))
    }
}

pub async fn resolve_conversation(client: Arc<Mutex<Client>>, conversation_id: String) -> GetConversationResponse {
    let conversation_res: GetConversationResponse = Client::send_basic_message_typed(client.clone(), ActionType::GET_CONVERSATION, Some(&GetConversationRequest {
        conversationID: conversation_id.clone(),
        ..Default::default()
    })).await.unwrap();

    conversation_res
}

pub async fn resolve_media(client: Arc<Mutex<Client>>, media: MediaContent) -> Attachment {
    let tachyon_auth_token = client.lock().await.auth_data.tachyon_auth_token.clone();
    let req_body = DownloadAttachmentRequest {
        info: MessageField::some(AttachmentInfo {
            attachmentID: media.mediaID.clone(),
            encrypted: true,
            ..Default::default()
        }),
        authData: MessageField::some(AuthMessage {
            requestID:        Uuid::new_v4().into(),
            tachyonAuthToken: tachyon_auth_token,
            network:          "".into(),
            configVersion:    MessageField::some(config_version()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let req_body = base64::engine::general_purpose::STANDARD.encode(req_body.write_to_bytes().unwrap());
    let c = client.lock().await;
    let req = c.http_client.get(format!("{INSTANT_MESSAGING_BASE_URL}{UPLOAD_MEDIA_URL}")).headers(upload_headers(&req_body));
    let res = c.http_client.execute(req.build().unwrap()).await.unwrap();
    res.error_for_status_ref().unwrap();
    let encrypted_data = res.bytes().await.unwrap().to_vec();
    let attachment_data = gcm_decrypt(&media.decryptionKey, encrypted_data);
    Attachment {
        data: attachment_data,
        file_name: Some(media.mediaName),
        mime_type: media.mimeType,
    }
}