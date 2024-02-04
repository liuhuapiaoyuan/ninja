use std::collections::HashMap;

use axum::extract::Query;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;

use super::BUILD_ID;

use super::session::session::Session;

/// Create a JSON object with the session properties.
pub fn session_props(session: &Session) -> anyhow::Result<Value> {
    let expires = time::OffsetDateTime::from_unix_timestamp(session.expires)
        .map(|v| v.format(&Rfc3339))??;
    let props = serde_json::json!({
        "user": {
            "id": session.user_id,
            "name": session.email,
            "email": session.email,
            "image": null,
            "picture": null,
            "groups": [],
        },
        "expires" : expires,
        "accessToken": session.access_token,
        "authProvider": "auth0"
    });

    Ok(props)
}

/// Create a JSON object with the chat properties.
pub fn chat_props(s: &Session, query: Query<HashMap<String, String>>) -> Value {
    serde_json::json!({
        "props": {
            "pageProps": {
                "user": {
                    "id": s.user_id,
                    "name": s.email,
                    "email": s.email,
                    "image": null,
                    "picture": null,
                    "groups": [],
                },
                "serviceStatus": {},
                "userCountry": "US",
                "geoOk": true,
                "serviceAnnouncement": {
                    "paid": {},
                    "public": {}
                },
                "isUserInCanPayGroup": true
            },
            "__N_SSP": true
        },
        "page": "/[[...default]]",
        "query": query.0,
        "buildId": BUILD_ID,
        "assetPrefix": "https://cdn.oaistatic.com",
        "isFallback": false,
        "gssp": true,
        "scriptLoader": []
    })
}

/// Create a JSON object with the chat gizmo properties.
pub fn chat_gizmo_props(s: &Session, query: Query<HashMap<String, String>>) -> Value {
    serde_json::json!({
        "props": {
            "pageProps": {
                "userCountry": "US",
                "user": {
                    "id": s.user_id,
                    "name": s.email,
                    "email": s.email,
                    "image": null,
                    "picture": null,
                    "groups": [],
                },
                "ageVerificationDeadline": null,
                "canManageBrowserStorage": false,
                "gizmo": null,
                "kind": "chat_page",
                "serverPrimedAllowBrowserStorageValue": true,
                "serviceAnnouncement": {
                    "paid": {},
                    "public": {}
                },
                "serviceStatus": {},
                "showCookieConsentBanner": false,
            },
            "__N_SSP": true
        },
        "page": "/g/[gizmoId]",
        "query": query.0,
        "buildId": BUILD_ID,
        "assetPrefix": "https://cdn.oaistatic.com",
        "isFallback": false,
        "gssp": true,
        "scriptLoader": []
    })
}
pub fn chat_gizmo_chat_props(s: &Session, query: Query<HashMap<String, String>>) -> Value {
    serde_json::json!({
        "props": {
            "pageProps": {
                "userCountry": "US",
                "user": {
                    "id": s.user_id,
                    "name": s.email,
                    "email": s.email,
                    "image": null,
                    "picture": null,
                    "groups": [],
                },
                "ageVerificationDeadline": null,
                "canManageBrowserStorage": false,
                "serverPrimedAllowBrowserStorageValue": true,
                "serviceAnnouncement": {
                    "paid": {},
                    "public": {}
                },
                "serviceStatus": {},
                "showCookieConsentBanner": false,
            },
            "__N_SSP": true
        },
        "page": "/g/[gizmoId]/c/[convId]",
        "query": query.0,
        "buildId": BUILD_ID,
        "assetPrefix": "https://cdn.oaistatic.com",
        "isFallback": false,
        "gssp": true,
        "scriptLoader": []
    })
}

/// Create a JSON object with the chat info properties.
pub fn chat_info_props(session: &Session) -> Value {
    serde_json::json!({
        "pageProps": {
            "user": {
                "id": session.user_id,
                "name": session.email,
                "email": session.email,
                "image": null,
                "picture": null,
                "groups": [],
            },
            "serviceStatus": {},
            "userCountry": "US",
            "geoOk": true,
            "serviceAnnouncement": {
                "paid": {},
                "public": {}
            },
            "isUserInCanPayGroup": true
        },
        "__N_SSP": true
    })
}
/// Create a JSON object with the gpts properties.
pub fn gpts_props(session: &Session) -> Value {
 
    serde_json::json!({
        "page": "/gpts",
        "query": {},
        "buildId": BUILD_ID,
        "assetPrefix": "",
        "isFallback": false,
        "gssp": true,
        "scriptLoader": [],
       "props":{
        "pageProps": {
            "user": {
                "id": session.user_id,
                "name": session.email,
                "email": session.email,
                "image": null,
                "picture": null,
                "groups": [],
            },
            
            "userCountry": "US",
            "geoOk": true,
            "serviceStatus": {},
            "userCountry": "US",
            "serviceAnnouncement": { "public": {}, "paid": {} },
            "serverPrimedAllowBrowserStorageValue": true,
            "canManageBrowserStorage": false,
            "ageVerificationDeadline": null,
            "showCookieConsentBanner": false
        },
        "__N_SSP": true
       }
    })
}
/// Create a JSON object with the gpts Discovery properties.
pub fn gpts_discovery_props(session: &Session) -> Value {
 
    serde_json::json!({
        "page": "/gpts/discovery",
        "query": {},
        "buildId": BUILD_ID,
        "assetPrefix": "",
        "isFallback": false,
        "gssp": true,
        "scriptLoader": [] ,
       "props":{
        "pageProps": {
            "user": {
                "id": session.user_id,
                "name": session.email,
                "email": session.email,
                "image": null,
                "picture": null,
                "groups": [],
            },
            
            "userCountry": "US",
            "geoOk": true,
            "serviceStatus": {},
            "userCountry": "US",
            "serviceAnnouncement": { "public": {}, "paid": {} },
            "serverPrimedAllowBrowserStorageValue": true,
            "canManageBrowserStorage": false,
            "ageVerificationDeadline": null,
            "showCookieConsentBanner": false
        },
        "__N_SSP": true
       }
    })
}
/// Create a JSON object with the gpts Editor properties.
pub fn gpts_editor_props(session: &Session) -> Value {
 
    serde_json::json!({
        "page": "/gpts/editor",
        "query": {},
        "buildId": BUILD_ID,
        "assetPrefix": "",
        "isFallback": false,
        "gssp": true,
        "scriptLoader": [] ,
       "props":{
        "pageProps": {
            "user": {
                "id": session.user_id,
                "name": session.email,
                "email": session.email,
                "image": null,
                "picture": null,
                "groups": [],
            },
            
            "userCountry": "US",
            "geoOk": true,
            "serviceStatus": {},
            "userCountry": "US",
            "serviceAnnouncement": { "public": {}, "paid": {} },
            "serverPrimedAllowBrowserStorageValue": true,
            "canManageBrowserStorage": false,
            "ageVerificationDeadline": null,
            "showCookieConsentBanner": false
        },
        "__N_SSP": true
       }
    })
}
///  Create a JSON object with the gpts Mine properties.
pub fn gpts_mine_props(session: &Session) -> Value {
 
    serde_json::json!({
        "page": "/gpts/mine",
        "query": {},
        "buildId": BUILD_ID,
        "assetPrefix": "",
        "isFallback": false,
        "gssp": true,
        "scriptLoader": [] ,
       "props":{
        "pageProps": {
            "user": {
                "id": session.user_id,
                "name": session.email,
                "email": session.email,
                "image": null,
                "picture": null,
                "groups": [],
            },
            
            "userCountry": "US",
            "geoOk": true,
            "serviceStatus": {},
            "userCountry": "US",
            "serviceAnnouncement": { "public": {}, "paid": {} },
            "serverPrimedAllowBrowserStorageValue": true,
            "canManageBrowserStorage": false,
            "ageVerificationDeadline": null,
            "showCookieConsentBanner": false
        },
        "__N_SSP": true
       }
    })
}
pub fn gpts_eidtor_slug_props(session: &Session , query: Query<HashMap<String, String>>) -> Value {
 
    serde_json::json!({
        "page": "/gpts/editor/[slug]",
        "query": query.0,
        "buildId": BUILD_ID,
        "assetPrefix": "",
        "isFallback": false,
        "gssp": true,
        "scriptLoader": [] ,
       "props":{
        "pageProps": {
            "user": {
                "id": session.user_id,
                "name": session.email,
                "email": session.email,
                "image": null,
                "picture": null,
                "groups": [],
            },
            
            "userCountry": "US",
            "geoOk": true,
            "serviceStatus": {},
            "userCountry": "US",
            "serviceAnnouncement": { "public": {}, "paid": {} },
            "serverPrimedAllowBrowserStorageValue": true,
            "canManageBrowserStorage": false,
            "ageVerificationDeadline": null,
            "showCookieConsentBanner": false
        },
        "__N_SSP": true
       }
    })
}

/// Create a JSON object with the share chat for ok properties.
pub fn share_chat_for_ok_props(share_id: String, share_data: Value) -> Value {
    serde_json::json!({
            "props": {
                "pageProps": {
                    "sharedConversationId": share_id,
                    "serverResponse": {
                        "type": "data",
                        "data": share_data
                    },
                    "continueMode": false,
                    "moderationMode": false,
                    "chatPageProps": {},
                },
                "__N_SSP": true
            },
            "page": "/share/[[...shareParams]]",
            "query": {
                "shareParams": vec![share_id]
            },
            "buildId": BUILD_ID,
            "assetPrefix": "https://cdn.oaistatic.com",
            "isFallback": false,
            "gssp": true,
            "scriptLoader": []
        }
    )
}

/// Create a JSON object with the share chat for error properties.
pub fn share_chat_for_err_props() -> Value {
    serde_json::json!({
        "props": {
            "pageProps": {"statusCode": 404}
        },
        "page": "/_error",
        "query": {},
        "buildId": BUILD_ID,
        "assetPrefix": "https://cdn.oaistatic.com",
        "nextExport": true,
        "isFallback": false,
        "gip": true,
        "scriptLoader": []
    })
}

/// Create a JSON object with the share chat info properties.
pub fn share_chat_info_props(share_id: String, share_data: Value) -> Value {
    serde_json::json!({
        "pageProps": {
            "sharedConversationId": share_id,
            "serverResponse": {
                "type": "data",
                "data": share_data,
            },
            "continueMode": false,
            "moderationMode": false,
            "chatPageProps": {},
        },
        "__N_SSP": true
    }
    )
}

/// Create a JSON object with the share chat continue info properties.
pub fn share_chat_continue_info_props(
    session: &Session,
    share_id: String,
    share_data: Value,
) -> Value {
    serde_json::json!({
        "pageProps": {
            "user": {
                "id": session.user_id,
                "name": session.email,
                "email": session.email,
                "image": null,
                "picture": null,
                "groups": [],
            },
            "serviceStatus": {},
            "userCountry": "US",
            "geoOk": true,
            "serviceAnnouncement": {
                "paid": {},
                "public": {}
            },
            "isUserInCanPayGroup": true,
            "sharedConversationId": share_id,
            "serverResponse": {
                "type": "data",
                "data": share_data,
            },
            "continueMode": true,
            "moderationMode": false,
            "chatPageProps": {
                "user": {
                    "id": session.user_id,
                    "name": session.email,
                    "email": session.email,
                    "image": null,
                    "picture": null,
                    "groups": [],
                },
                "serviceStatus": {},
                "userCountry": "US",
                "geoOk": true,
                "serviceAnnouncement": {
                    "paid": {},
                    "public": {}
                },
                "isUserInCanPayGroup": true,
            },
        },
        "__N_SSP": true
    })
}

/// Create a JSON object with the error properties.
pub fn error_404_props() -> Value {
    serde_json::json!(
        {
            "props": {
                "pageProps": {"statusCode": 404}
            },
            "page": "/_error",
            "query": {},
            "buildId": BUILD_ID,
            "assetPrefix": "https://cdn.oaistatic.com",
            "nextExport": true,
            "isFallback": false,
            "gip": false,
            "scriptLoader": []
        }
    )
}
