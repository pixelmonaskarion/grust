use std::{collections::HashMap, fs::File, io::{self, Read, Write}, path::Path, sync::Arc};

use browser::open_browser;
use client::Client;
use google_oauth::exchange_for_oauth;
use image::Luma;
use reqwest::{cookie::{CookieStore, Jar}, Url};
use serde_json::Value;
use tokio::sync::Mutex;

pub const MESSAGES_BASE_URL: &'static str = "https://messages.google.com";

pub const INSTANT_MESSAGING_BASE_URL: &'static str = "https://instantmessaging-pa.googleapis.com";
pub const INSTANT_MESSAGING_BASE_URLGOOGLE: &'static str = "https://instantmessaging-pa.clients6.google.com";

const REGISTRATION_BASE_URL: &'static str = "/$rpc/google.internal.communications.instantmessaging.v1.Registration";
const SIGN_IN_GAIA_URL: &'static str = "/SignInGaia";

pub const CONFIG_URL: &'static str = "https://messages.google.com/web/config";

pub const GOOGLE_NETWORK: &'static str = "GDitto";

pub const QR_CODE_URL_BASE: &'static str = "https://support.google.com/messages/?p=web_computer#?c=";
const QR_NETWORK: &'static str = "Bugle";
const USER_AGENT: &'static str = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36";
const REGISTER_PHONE_RELAY_URL: &'static str = "/RegisterPhoneRelay";
const PAIRING_BASE_URL: &'static str = "/$rpc/google.internal.communications.instantmessaging.v1.Pairing";
const REGISTER_REFRESH_URL: &'static str = "/RegisterRefresh";
const RECEIVE_MESSAGES_URL: &'static str = "/ReceiveMessages";
const MESSAGING_BASE_URL: &'static str = "/$rpc/google.internal.communications.instantmessaging.v1.Messaging";

mod protos;
mod client;
mod crypto;
mod google_oauth;
mod browser;

#[tokio::main]
async fn main() {
    let client = Arc::new(Mutex::new(Client::new().await));
    let (qr_data, long_poll_handle) = Client::start_login(client).await;
    let qrcode = qrcode::QrCode::new(qr_data.as_bytes()).unwrap();
    qrcode.render::<Luma<u8>>().build().save("qrcode.png").unwrap();
    let _ = long_poll_handle.await;
    // let code_string = qrcode.render()
    //     .dark_color(' ')
    //     .light_color('#')
    //     .build();
    // println!("{code_string}");
}