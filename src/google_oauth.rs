use google_jwt_auth::{usage::Usage, AuthConfig};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

// #[derive(Serialize, Deserialize)]
// pub struct OauthToken {
//     pub access_token: String,
//     pub expires_in: u64,
//     pub token_type: String,
// }

const CLIENT_ID: &'static str = "I'm not putting this on github";
const CLIENT_SECRET: &'static str = "";

pub async fn exchange_for_oauth(client: &Client, jwt: &str) -> String {
    // let token_endpoint = "https://oauth2.googleapis.com/token";
    // let data = json!({
    //     "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
    //     "assertion": jwt,
    // });
    // let req = client.post(token_endpoint)
    //     .body(serde_json::to_string(&data).unwrap())
    //     .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
    //     .build().unwrap();
    // let res = client.execute(req).await.unwrap();
    // println!("{}", res.text().await.unwrap());
    // todo!();
    // let token_data: OauthToken = res.json().await.unwrap();
    // return token_data;
    let auth_config = AuthConfig::build(include_str!("service.json"), &Usage::OpenId).unwrap();
    let token = auth_config.generate_auth_token(3600).await.unwrap();
    println!("{token}");
    token
}

