mod cookier;
mod extract;

use anyhow::anyhow;
use axum::body;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::Path;
use axum::extract::Query;
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::http::header;
use axum::http::response::Builder;
use axum::http::HeaderMap;
use axum::http::Response;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::any;
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use axum::TypedHeader;
use axum_csrf::CsrfConfig;
use axum_csrf::CsrfLayer;
use axum_csrf::CsrfToken;
use axum_csrf::Key;
use axum_extra::extract::CookieJar;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::OnceLock;
use time::format_description::well_known::Rfc3339;
use tower::ServiceBuilder;
use tower_http::ServiceBuilderExt;

use crate::constant::API_AUTH_SESSION_COOKIE_KEY;
use crate::constant::ARKOSE_ENDPOINT;
use crate::constant::AUTH_KEY;
use crate::constant::CSRF_TOKEN;
use crate::constant::EMPTY;
use crate::constant::ERROR;
use crate::constant::PICTURE;
use crate::constant::SITE_KEY;
use crate::constant::SUPPORT_APPLE;
use crate::constant::USERNAME;
use crate::context::args::Args;
use crate::debug;
use crate::info;
use crate::now_duration;
use crate::serve::error::ResponseError;
use crate::serve::middleware::csrf;
use crate::serve::proxy::header_convert;
use crate::serve::route::ui::extract::SessionExtractor;
use crate::serve::turnstile;
use crate::serve::whitelist;
use crate::with_context;
use crate::{
    auth::{model::AuthAccount, provide::AuthProvider},
    token::model::Token,
    URL_CHATGPT_API,
};

use self::extract::Session;

use super::get_static_resource;

const DEFAULT_INDEX: &str = "/";
const LOGIN_INDEX: &str = "/auth/login";
const SESSION_ID: &str = "ninja_session";
const PUID_ID: &str = "_puid";
const BUILD_ID: &str = "eFlZtDCQUjuHAccnRY3au";
const TEMP_404: &str = "404.htm";
const TEMP_AUTH: &str = "auth.htm";
const TEMP_CHAT: &str = "chat.htm";
const TEMP_DETAIL: &str = "detail.htm";
const TEMP_LOGIN: &str = "login.htm";
const TEMP_SHARE: &str = "share.htm";

static TEMPLATE: OnceLock<tera::Tera> = OnceLock::new();

// this function could be located in a different module
pub(super) fn config(router: Router, args: &Args) -> Router {
    // If the UI is disabled, then return the router directly
    if args.disable_ui {
        return router;
    }

    if let Some(endpoint) = with_context!(arkose_endpoint) {
        info!("WebUI site use Arkose endpoint: {endpoint}")
    }

    let mut tera = tera::Tera::default();
    tera.add_raw_templates(vec![
        (TEMP_404, include_str!("../../../../ui/404.htm")),
        (TEMP_AUTH, include_str!("../../../../ui/auth.htm")),
        (TEMP_LOGIN, include_str!("../../../../ui/login.htm")),
        (TEMP_CHAT, include_str!("../../../../ui/chat.htm")),
        (TEMP_DETAIL, include_str!("../../../../ui/detail.htm")),
        (TEMP_SHARE, include_str!("../../../../ui/share.htm")),
    ])
    .expect("The static template failed to load");

    let _ = TEMPLATE.set(tera);

    let config = CsrfConfig::default().with_key(Some(Key::generate()));

    let router = if with_context!(auth_key).is_some() {
        router
    } else {
        router.route("/auth", get(get_auth))
    };

    router
        .route(
            "/auth/login",
            post(post_login).layer(
                ServiceBuilder::new()
                    .map_request_body(body::boxed)
                    .layer(middleware::from_fn(csrf::csrf_middleware)),
            ),
        )
        .route("/auth/login", get(get_login))
        .layer(CsrfLayer::new(config))
        .route("/auth/login/token", post(post_login_token))
        .route("/auth/logout", get(get_logout))
        .route("/auth/session", get(get_session))
        .route("/auth/me", get(get_auth_me))
        .route("/", get(get_chat))
        .route("/c", get(get_chat))
        .route("/c/:conversation_id", get(get_chat))
        .route(
            "/chat",
            any(|| async {
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(header::LOCATION, "/")
                    .body(Body::empty())
                    .expect("An error occurred while redirecting")
            }),
        )
        .route(
            "/chat/:conversation_id",
            any(|| async {
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(header::LOCATION, "/")
                    .body(Body::empty())
                    .expect("An error occurred while redirecting")
            }),
        )
        .route("/share/e/:share_id", get(get_share_chat))
        .route("/share/:share_id", get(get_share_chat))
        .route("/share/:share_id/continue", get(get_share_chat_continue))
        .route(
            &format!("/_next/data/{BUILD_ID}/index.json"),
            get(get_chat_info),
        )
        .route(
            // {conversation_id}.json
            &format!("/_next/data/{BUILD_ID}/c/:conversation_id"),
            get(get_chat_info),
        )
        .route(
            // {share_id}.json
            &format!("/_next/data/{BUILD_ID}/share/:share_id"),
            get(get_share_chat_info),
        )
        .route(
            &format!("/_next/data/{BUILD_ID}/share/:share_id/continue.json"),
            get(get_share_chat_continue_info),
        )
        // static resource endpoints
        .route("/resources/*path", get(get_static_resource))
        .route("/_next/static/*path", get(get_static_resource))
        .route("/fonts/*path", get(get_static_resource))
        .route("/ulp/*path", get(get_static_resource))
        .route("/sweetalert2/*path", get(get_static_resource))
        // 404 endpoint
        .fallback(error_404)
}

async fn get_auth(token: CsrfToken) -> Result<impl IntoResponse, ResponseError> {
    let mut ctx = tera::Context::new();
    ctx.insert(CSRF_TOKEN, &token.authenticity_token()?);
    settings_template_data(&mut ctx);
    let tm = render_template(TEMP_AUTH, &ctx)?;
    Ok((token, tm))
}

async fn get_login(token: CsrfToken) -> Result<impl IntoResponse, ResponseError> {
    let mut ctx = tera::Context::new();
    ctx.insert(CSRF_TOKEN, &token.authenticity_token()?);
    ctx.insert(ERROR, EMPTY);
    ctx.insert(USERNAME, EMPTY);
    settings_template_data(&mut ctx);
    let tm = render_template(TEMP_LOGIN, &ctx)?;
    Ok((token, tm))
}

/// Login from username and password
async fn post_login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    token: CsrfToken,
    account: axum::Form<AuthAccount>,
) -> Result<impl IntoResponse, ResponseError> {
    // Check if the request is in the whitelist
    whitelist::check_whitelist(&account.username)?;

    // Check if the request is in the turnstile
    turnstile::cf_turnstile_check(&addr.ip(), account.cf_turnstile_response.as_deref()).await?;

    match with_context!(auth_client).do_access_token(&account).await {
        Ok(access_token) => {
            let authentication_token =
                Token::try_from(access_token).map_err(ResponseError::InternalServerError)?;
            let session = Session::from(authentication_token);

            let cookie = cookier::build_cookie(SESSION_ID, session.to_string(), session.expires)?;

            let mut builder = Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(header::LOCATION, DEFAULT_INDEX)
                .header(header::SET_COOKIE, cookie.to_string());

            if let Some(value) = session.session_token {
                let session_cookie =
                    cookier::build_cookie(API_AUTH_SESSION_COOKIE_KEY, value, session.expires)?;
                builder = builder.header(header::SET_COOKIE, session_cookie.to_string())
            }

            Ok(builder
                .body(Body::empty())
                .map_err(ResponseError::InternalServerError)?
                .into_response())
        }
        Err(err) => {
            let mut ctx = tera::Context::new();
            ctx.insert(CSRF_TOKEN, &token.authenticity_token()?);
            ctx.insert(USERNAME, &account.username);
            ctx.insert(ERROR, &err.to_string());
            let tm = render_template(TEMP_LOGIN, &ctx)?;
            Ok((token, tm).into_response())
        }
    }
}

/// Login from access token / refresh token / session token
async fn post_login_token(
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, ResponseError> {
    let access_token = bearer.token();

    if access_token.is_empty() {
        return Err(ResponseError::TempporaryRedirect(LOGIN_INDEX));
    }

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::LOCATION, DEFAULT_INDEX);

    // Check input token type
    let session = match access_token {
        s if s.split('.').count() == 3 => {
            let token_prefile = crate::token::check(s)
                .map_err(ResponseError::Unauthorized)?
                .ok_or(ResponseError::InternalServerError(anyhow!(
                    "get access token profile error"
                )))?;
            // Check if the request is in the whitelist
            whitelist::check_whitelist(&token_prefile.email())?;
            Session::from((s, token_prefile))
        }
        s if s.len() > 40 && s.len() < 100 => {
            let refresh_token = with_context!(auth_client)
                .do_refresh_token(access_token)
                .await
                .map_err(ResponseError::BadRequest)?;
            let authentication_token =
                Token::try_from(refresh_token).map_err(ResponseError::InternalServerError)?;
            Session::from(authentication_token)
        }
        _ => {
            let access_token = with_context!(auth_client)
                .do_session(access_token)
                .await
                .map_err(ResponseError::BadRequest)?;
            let authentication_token =
                Token::try_from(access_token).map_err(ResponseError::InternalServerError)?;
            Session::from(authentication_token)
        }
    };

    // Consider using secure(true) based on your security requirements
    let cookie = cookier::build_cookie(SESSION_ID, session.to_string(), session.expires)?;

    // Set session cookie
    builder = builder.header(header::SET_COOKIE, cookie.to_string());

    // If the session not empty, then set session token
    if let Some(value) = session.session_token {
        let session_cookie =
            cookier::build_cookie(API_AUTH_SESSION_COOKIE_KEY, value, session.expires)?;
        builder = builder.header(header::SET_COOKIE, session_cookie.to_string())
    }

    let response = builder
        .body(Body::empty())
        .map_err(ResponseError::InternalServerError)?;

    Ok(response)
}

async fn get_logout(extract: SessionExtractor) -> Result<Response<Body>, ResponseError> {
    // If the session is empty, then redirect to the login page
    if let Some(refresh_token) = extract.session.refresh_token {
        if let Some(err) = with_context!(auth_client)
            .do_revoke_token(&refresh_token)
            .await
            .err()
        {
            debug!("Revoke token error: {}", err);
        }
    }

    // Clear session
    let session_cookie = cookier::clear_cookie(SESSION_ID);

    // Clear puid
    let puid_cookie = cookier::clear_cookie(PUID_ID);

    // Redirect to login page
    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, LOGIN_INDEX)
        .header(header::SET_COOKIE, session_cookie.to_string())
        .header(header::SET_COOKIE, puid_cookie.to_string())
        .body(Body::empty())
        .map_err(ResponseError::InternalServerError)?)
}

async fn get_session(extract: SessionExtractor) -> Result<Response<Body>, ResponseError> {
    // Compare the current timestamp with the expiration time of the session
    let current_timestamp = now_duration()?.as_secs() as i64;
    if extract.session.expires < current_timestamp {
        return Err(ResponseError::TempporaryRedirect(LOGIN_INDEX));
    }

    // Refresh session
    if extract.session.expires - current_timestamp <= 21600 {
        let ctx = with_context!();
        let new_session = if let Some(c) = extract.session_token {
            match ctx.auth_client().do_session(&c).await {
                Ok(access_token) => {
                    let authentication_token = Token::try_from(access_token)?;
                    Some(Session::from(authentication_token))
                }
                Err(err) => {
                    debug!("Get session token error: {}", err);
                    None
                }
            }
        } else if let Some(refresh_token) = extract.session.refresh_token.as_ref() {
            match ctx.auth_client().do_refresh_token(&refresh_token).await {
                Ok(new_refresh_token) => {
                    let authentication_token = Token::try_from(new_refresh_token)?;
                    Some(Session::from(authentication_token))
                }
                Err(err) => {
                    debug!("Refresh token error: {}", err);
                    None
                }
            }
        } else {
            None
        };

        if let Some(new_session) = new_session {
            return create_response_from_session(&new_session);
        }
    }

    create_response_from_session(&extract.session)
}

fn create_response_from_session(session: &Session) -> Result<Response<Body>, ResponseError> {
    let body = session_to_body(session)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::LOCATION, LOGIN_INDEX)
        .header(header::SET_COOKIE, session.to_string()) // Note: This might not be what you want
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(body))
        .map_err(ResponseError::InternalServerError)?)
}

fn session_to_body(session: &Session) -> anyhow::Result<String> {
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
    Ok(props.to_string())
}

async fn get_auth_me(
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<impl IntoResponse, ResponseError> {
    let headers_client = header_convert(&headers, &jar, URL_CHATGPT_API)?;
    // 打印一下headers
    for (key, value) in headers_client.iter() {
        println!("{}: {:?}", key, value);
    }
    let resp = with_context!(api_client)
        .get(format!("{URL_CHATGPT_API}/backend-api/me"))
        .headers(headers_client)
        .send()
        .await
        .map_err(ResponseError::InternalServerError)?;

    let status = resp.status();
    let headers = resp.headers().clone();



    let bytes = resp
        .bytes()
        .await
        .map_err(ResponseError::InternalServerError)?;

    match serde_json::from_slice::<Value>(&bytes) {
        Ok(mut json) => {
            json.as_object_mut()
                .map(|v| v.insert(PICTURE.to_owned(), Value::Null));
            Ok(Json(json).into_response())
        }
        Err(_err) => {
            let mut builder = Builder::new().status(status);
            builder.headers_mut().map(|h| h.extend(headers));
            Ok(builder
                .body(Body::from(bytes))
                .map_err(ResponseError::InternalServerError)?
                .into_response())
        }
    }
}

async fn get_chat(
    conversation_id: Option<Path<String>>,
    mut query: Query<HashMap<String, String>>,
    extract: SessionExtractor,
) -> Result<Response<Body>, ResponseError> {
    let template_name = match conversation_id {
        Some(conversation_id) => {
            query.insert("default".to_string(), format!("[c, {}]", conversation_id.0));
            TEMP_DETAIL
        }
        None => TEMP_CHAT,
    };
    let props = serde_json::json!({
        "props": {
            "pageProps": {
                "user": {
                    "id": extract.session.user_id,
                    "name": extract.session.email,
                    "email": extract.session.email,
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
    });
    let mut ctx = tera::Context::new();
    ctx.insert(
        "props",
        &serde_json::to_string(&props).map_err(ResponseError::InternalServerError)?,
    );
    settings_template_data(&mut ctx);
    return render_template(template_name, &ctx);
}

async fn get_chat_info(extract: SessionExtractor) -> Result<Response<Body>, ResponseError> {
    let body = serde_json::json!({
        "pageProps": {
            "user": {
                "id": extract.session.user_id,
                "name": extract.session.email,
                "email": extract.session.email,
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
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(body.to_string()))
        .map_err(ResponseError::InternalServerError)?)
}

async fn get_share_chat(
    share_id: Path<String>,
    extract: SessionExtractor,
) -> Result<Response<Body>, ResponseError> {
    let share_id = share_id.0;
    let resp = with_context!(api_client)
        .get(format!("{URL_CHATGPT_API}/backend-api/share/{share_id}"))
        .headers(header_convert(
            &extract.headers,
            &extract.jar,
            URL_CHATGPT_API,
        )?)
        .send()
        .await
        .map_err(ResponseError::InternalServerError)?;

    return match resp.json::<Value>().await {
        Ok(mut share_data) => {
            if let Some(replace) = share_data
                .get_mut("continue_conversation_url")
                .and_then(|v| v.as_str())
            {
                let new_value = replace.replace("https://chat.openai.com", "");
                share_data.as_object_mut().and_then(|data| {
                    data.insert("continue_conversation_url".to_owned(), json!(new_value))
                });
            }

            let props = serde_json::json!({
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
            );
            let mut ctx = tera::Context::new();
            ctx.insert(
                "props",
                &serde_json::to_string(&props).map_err(ResponseError::InternalServerError)?,
            );
            settings_template_data(&mut ctx);
            render_template(TEMP_SHARE, &ctx)
        }
        Err(_) => {
            let props = serde_json::json!({
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
            });

            let mut ctx = tera::Context::new();
            ctx.insert(
                "props",
                &serde_json::to_string(&props).map_err(ResponseError::InternalServerError)?,
            );
            settings_template_data(&mut ctx);
            render_template(TEMP_404, &ctx)
        }
    };
}

async fn get_share_chat_info(
    share_id: Path<String>,
    extract: SessionExtractor,
) -> Result<Response<Body>, ResponseError> {
    let share_id = share_id.0.replace(".json", EMPTY);
    let resp = with_context!(api_client)
        .get(format!("{URL_CHATGPT_API}/backend-api/share/{share_id}"))
        .headers(header_convert(
            &extract.headers,
            &extract.jar,
            URL_CHATGPT_API,
        )?)
        .send()
        .await
        .map_err(ResponseError::InternalServerError)?;

    return match resp.json::<Value>().await {
        Ok(mut share_data) => {
            if let Some(replace) = share_data
                .get_mut("continue_conversation_url")
                .and_then(|v| v.as_str())
            {
                let new_value = replace.replace("https://chat.openai.com", "");
                share_data.as_object_mut().and_then(|data| {
                    data.insert("continue_conversation_url".to_owned(), json!(new_value))
                });
            }

            let props = serde_json::json!({
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
            );
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_string(&props).map_err(ResponseError::InternalServerError)?,
                ))
                .map_err(ResponseError::InternalServerError)?)
        }
        Err(_) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({"notFound": true}))
                    .map_err(ResponseError::InternalServerError)?,
            ))
            .map_err(ResponseError::InternalServerError)?),
    };
}

async fn get_share_chat_continue(share_id: Path<String>) -> Result<Response<Body>, ResponseError> {
    Ok(Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(header::LOCATION, format!("/share/{}", share_id.0))
        .body(Body::empty())
        .map_err(ResponseError::InternalServerError)?)
}

async fn get_share_chat_continue_info(
    share_id: Path<String>,
    extract: SessionExtractor,
) -> Result<Response<Body>, ResponseError> {
    let resp = with_context!(api_client)
        .get(format!(
            "{URL_CHATGPT_API}/backend-api/share/{}",
            share_id.0
        ))
        .headers(header_convert(
            &extract.headers,
            &extract.jar,
            URL_CHATGPT_API,
        )?)
        .send()
        .await
        .map_err(ResponseError::InternalServerError)?;
    match resp.json::<Value>().await {
        Ok(mut share_data) => {
            if let Some(replace) = share_data
                .get_mut("continue_conversation_url")
                .and_then(|v| v.as_str())
            {
                let new_value = replace.replace("https://chat.openai.com", "");
                share_data.as_object_mut().and_then(|data| {
                    data.insert("continue_conversation_url".to_owned(), json!(new_value))
                });
            }
            let props = serde_json::json!({
                "pageProps": {
                    "user": {
                        "id": extract.session.user_id,
                        "name": extract.session.email,
                        "email": extract.session.email,
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
                    "sharedConversationId": share_id.0,
                    "serverResponse": {
                        "type": "data",
                        "data": share_data,
                    },
                    "continueMode": true,
                    "moderationMode": false,
                    "chatPageProps": {
                        "user": {
                            "id": extract.session.user_id,
                            "name": extract.session.email,
                            "email": extract.session.email,
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
            });
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_string(&props).map_err(ResponseError::InternalServerError)?,
                ))
                .map_err(ResponseError::InternalServerError)?)
        }
        Err(_) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "same-origin")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({"notFound": true}))
                    .map_err(ResponseError::InternalServerError)?,
            ))
            .map_err(ResponseError::InternalServerError)?),
    }
}

async fn error_404() -> Result<Response<Body>, ResponseError> {
    let mut ctx = tera::Context::new();
    let props = json!(
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
    );
    ctx.insert(
        "props",
        &serde_json::to_string(&props).map_err(ResponseError::InternalServerError)?,
    );
    render_template(TEMP_404, &ctx)
}

/// Render html template
fn render_template(name: &str, context: &tera::Context) -> Result<Response<Body>, ResponseError> {
    let tm = TEMPLATE
        .get()
        .expect("template not init")
        .render(name, context)
        .map_err(ResponseError::InternalServerError)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime::TEXT_HTML_UTF_8.as_ref())
        .body(Body::from(tm))
        .map_err(ResponseError::InternalServerError)?)
}

/// Settings html template data
fn settings_template_data(ctx: &mut tera::Context) {
    let g_ctx = with_context!();

    g_ctx.auth_key().map(|_| {
        ctx.insert(AUTH_KEY, EMPTY);
    });

    g_ctx.cf_turnstile().map(|site_key| {
        ctx.insert(SITE_KEY, &site_key.site_key);
    });

    g_ctx.pop_preauth_cookie().map(|_| {
        ctx.insert(SUPPORT_APPLE, EMPTY);
    });

    g_ctx
        .arkose_endpoint()
        .map(|arkose_endpoint| ctx.insert(ARKOSE_ENDPOINT, arkose_endpoint));
}
