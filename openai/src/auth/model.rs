use std::{
    fmt::{Display, Formatter},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use typed_builder::TypedBuilder;

use crate::arkose::ArkoseToken;

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AuthStrategy {
    Apple,
    Web,
    Platform,
}

impl Default for AuthStrategy {
    fn default() -> Self {
        AuthStrategy::Web
    }
}

impl Display for AuthStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{self:?}")
    }
}

#[derive(Deserialize, TypedBuilder, Default)]
pub struct AuthAccount {
    pub username: String,
    pub password: String,
    #[builder(setter(into, strip_option), default)]
    pub mfa: Option<String>,
    #[builder(setter(into, strip_option), default)]
    pub csrf_token: Option<String>,
    #[serde(default)]
    pub option: AuthStrategy,
    #[builder(setter(into, strip_option), default)]
    pub arkose_token: Option<String>,
    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "cf-turnstile-response")]
    pub cf_turnstile_response: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OAuthAccessToken {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
    pub expires_in: i64,
}

#[derive(Serialize, Deserialize)]
pub struct SessionAccessToken {
    pub user: WebUser,
    pub expires: String,
    #[serde(rename = "accessToken")]
    pub access_token: String,
    #[serde(rename = "authProvider")]
    pub auth_provider: String,
    #[serde(rename = "refreshCookie")]
    pub refresh_cookie: Option<Session>,
    pub session_token: Option<Session>,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshToken {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    pub id_token: String,
    pub expires_in: i64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Session {
    pub value: String,
    pub expires: Option<SystemTime>,
}

impl Serialize for Session {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.value)
    }
}

#[derive(Deserialize)]
pub struct DashSession {
    pub object: String,
    pub user: DashUser,
    pub invites: Vec<Value>,
}

impl DashSession {
    pub fn sensitive_id(&self) -> &str {
        &self.user.session.sensitive_id
    }

    pub fn user_id(&self) -> &str {
        &self.user.id
    }

    pub fn nickname(&self) -> &str {
        &self.user.name
    }

    pub fn email(&self) -> &str {
        &self.user.email
    }

    pub fn picture(&self) -> &str {
        &self.user.picture
    }
}

#[derive(Deserialize)]
pub struct DashUser {
    pub object: String,
    pub id: String,
    pub email: String,
    pub name: String,
    pub picture: String,
    pub created: i64,
    pub session: DashUserSession,
}

#[derive(Deserialize, Serialize)]
pub struct DashUserSession {
    pub sensitive_id: String,
    pub object: String,
    pub name: Option<String>,
    pub created: i64,
    pub last_use: Option<i64>,
    pub publishable: bool,
}

#[derive(Deserialize)]
pub struct DashUserOrgsData {
    pub object: String,
    pub id: String,
    pub created: i64,
    pub title: String,
    pub name: String,
    pub description: String,
    pub personal: bool,
    pub is_default: bool,
    pub role: String,
    pub groups: Vec<Value>,
}

#[derive(Deserialize, Serialize)]
pub struct ApiKey {
    pub result: String,
    pub key: Option<Key>,
}

#[derive(Deserialize, Serialize)]
pub struct ApiKeyList {
    pub object: String,
    pub data: Vec<Key>,
}

#[derive(Deserialize, Serialize)]
pub struct Key {
    pub sensitive_id: String,
    pub object: String,
    pub name: Option<String>,
    pub created: i64,
    #[serde(rename = "last_use")]
    pub last_use: Value,
    pub publishable: bool,
}
#[derive(Deserialize, Serialize)]
pub struct WebUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub image: String,
    pub picture: String,
    pub idp: String,
    pub iat: i64,
    pub mfa: bool,
    pub groups: Vec<Value>,
    #[serde(rename = "intercom_hash")]
    pub intercom_hash: String,
}

pub enum AccessToken {
    Session(SessionAccessToken),
    OAuth(OAuthAccessToken),
}

impl Serialize for AccessToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            AccessToken::Session(web) => serializer.serialize_some(web),
            AccessToken::OAuth(apple) => serializer.serialize_some(apple),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Billing {
    pub total_granted: f64,
    pub total_used: f64,
    pub total_available: f64,
    pub total_paid_available: f64,
    pub grants: Grants,
}

#[derive(Serialize, Deserialize)]
pub struct Grants {
    pub data: Vec<Daum>,
}

#[derive(Serialize, Deserialize)]
pub struct Daum {
    pub object: String,
    pub id: String,
    pub grant_amount: f64,
    pub used_amount: f64,
    pub effective_at: f64,
    pub expires_at: f64,
}

#[derive(Serialize, TypedBuilder)]
pub struct ApiKeyData<'a> {
    action: ApiKeyAction,
    #[builder(setter(into, strip_option), default)]
    name: Option<&'a str>,
    #[builder(setter(into, strip_option), default)]
    redacted_key: Option<&'a str>,
    #[builder(setter(into, strip_option), default)]
    created_at: Option<u64>,
    arkose_token: &'a ArkoseToken,
}

#[derive(Clone)]
pub enum ApiKeyAction {
    Create,
    Update,
    Delete,
}

impl Serialize for ApiKeyAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ApiKeyAction::Create => serializer.serialize_str("create"),
            ApiKeyAction::Update => serializer.serialize_str("update"),
            ApiKeyAction::Delete => serializer.serialize_str("delete"),
        }
    }
}
