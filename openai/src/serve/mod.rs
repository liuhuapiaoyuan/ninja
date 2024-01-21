mod error;
mod middleware;
#[cfg(feature = "preauth")]
mod preauth;
mod proxy;
mod puid;
#[cfg(feature = "template")]
mod route;
mod signal;
mod turnstile;
mod whitelist;

use axum::body::Body;
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::http::Response;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use axum::Router;
use axum::{Json, TypedHeader};
use axum_server::{AddrIncomingConfig, Handle};

use self::proxy::ext::RequestExt;
use self::proxy::ext::SendRequestExt;
use self::proxy::resp::response_convert;
use crate::auth::model::{AccessToken, AuthAccount, RefreshToken, SessionAccessToken};
use crate::auth::provide::AuthProvider;
use crate::constant::API_AUTH_SESSION_COOKIE_KEY;
use crate::context;
use crate::context::args::Args;
use crate::proxy::{InnerProxy, Proxy};
use crate::serve::error::ProxyError;
use crate::serve::error::ResponseError;
use crate::serve::middleware::tokenbucket::{Strategy, TokenBucketLimitContext};
use crate::{info, warn, with_context};
use crate::{URL_CHATGPT_API, URL_PLATFORM_API};
use axum::http::header;
use axum_extra::extract::{cookie, CookieJar};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::HttpConfig;
use std::net::SocketAddr;
use std::ops::Not;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_http::trace;
use tracing::Level;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

type ProxyResult<T> = std::result::Result<T, ProxyError>;

fn print_boot_message(inner: &Args) {
    info!("OS: {}", std::env::consts::OS);
    info!("Arch: {}", std::env::consts::ARCH);
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Concurrent limit: {}", inner.concurrent_limit);
    info!("Keepalive {} seconds", inner.tcp_keepalive);
    info!("Timeout {} seconds", inner.timeout);
    info!("Connect timeout {} seconds", inner.connect_timeout);
    info!("TCP keepalive: {}", inner.no_keepalive.not());
    info!("Cookie store: {}", inner.cookie_store);
    info!("File proxy: {}", inner.enable_file_proxy);
    info!("Direct connection: {}", inner.enable_direct);
    info!(
        "ArkoseLabs GPT-3.5 experiment: {}",
        inner.arkose_gpt3_experiment
    );
    info!(
        "ArkoseLabs GPT-3.5 experiment solver: {}",
        inner.arkose_gpt3_experiment_solver
    );
    inner.arkose_solver.as_ref().map(|solver| {
        info!("ArkoseLabs solver: {:?}", solver.solver);
    });

    inner.proxies.iter().for_each(|p| match p {
        Proxy::All(inner) | Proxy::Api(inner) | Proxy::Auth(inner) | Proxy::Arkose(inner) => {
            match inner {
                InnerProxy::Interface(ipaddr) => {
                    info!("{} | Interface bind: {ipaddr}", p.proto());
                }
                InnerProxy::Proxy(url) => {
                    info!("{} | Upstream proxy: {url}", p.proto());
                }
                InnerProxy::IPv6Subnet(ipv6_subnet) => {
                    info!("{} | IPv6 subnet: {ipv6_subnet}", p.proto());
                }
            }
        }
    });

    info!(
        "Starting HTTP(S) server at http(s)://{:?}",
        inner.bind.expect("bind address required")
    );
}

pub struct Serve(Args);

impl Serve {
    pub fn new(inner: Args) -> Self {
        Self(inner)
    }

    /// from issue: https://github.com/hyperium/hyper/issues/3140
    #[tokio::main]
    pub async fn run(self) -> anyhow::Result<()> {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "RUST_LOG=warn".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        // print boot message
        print_boot_message(&self.0);

        // init context
        context::init(self.0.clone());

        // init global layer provider
        let global_layer = tower::ServiceBuilder::new()
            .layer(
                tower_http::trace::TraceLayer::new_for_http()
                    .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                    .on_response(trace::DefaultOnResponse::new().level(Level::INFO))
                    .on_request(trace::DefaultOnRequest::new().level(Level::INFO))
                    .on_failure(trace::DefaultOnFailure::new().level(Level::WARN)),
            )
            .layer(tower::limit::ConcurrencyLimitLayer::new(
                self.0.concurrent_limit,
            ))
            .layer(
                tower_http::cors::CorsLayer::new()
                    .allow_credentials(true)
                    .allow_headers(tower_http::cors::AllowHeaders::mirror_request())
                    .allow_methods(tower_http::cors::AllowMethods::mirror_request())
                    .allow_origin(tower_http::cors::AllowOrigin::mirror_request()),
            )
            .layer(axum::error_handling::HandleErrorLayer::new(
                |_: axum::BoxError| async { axum::http::StatusCode::REQUEST_TIMEOUT },
            ))
            .layer(tower::timeout::TimeoutLayer::new(Duration::from_secs(
                self.0.timeout as u64,
            )))
            .layer(axum::extract::DefaultBodyLimit::max(200 * 1024 * 1024));

        // init auth layer provider
        let app_layer = {
            let limit_context = TokenBucketLimitContext::from((
                Strategy::from_str(self.0.tb_store_strategy.as_str())?,
                self.0.tb_enable,
                self.0.tb_capacity,
                self.0.tb_fill_rate,
                self.0.tb_expired,
                self.0.tb_redis_url.clone(),
            ));

            tower::ServiceBuilder::new()
                .layer(axum::middleware::from_fn(
                    middleware::auth::token_middleware,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(limit_context),
                    middleware::limit::limit_middleware,
                ))
        };

        let router = route::config(
            Router::new()
                // official dashboard api endpoint
                .route("/dashboard/*path", any(official_proxy))
                // official v1 api endpoint
                .route("/v1/*path", any(official_proxy))
                // unofficial backend api endpoint
                .route("/backend-api/*path", any(unofficial_proxy))
                .route_layer(app_layer)
                // unofficial public api endpoint
                .route("/public-api/*path", any(unofficial_proxy))
                .route("/auth/token", post(post_access_token))
                .route("/getsession", post(post_access_token))
                .route("/auth/refresh_token", post(post_refresh_token))
                .route("/auth/revoke_token", post(post_revoke_token))
                .route("/auth/refresh_session", get(get_session)),
            &self.0,
        )
        .layer(global_layer);

        // Signal the server to shutdown using Handle.
        let handle = Handle::new();

        // Spawn a task to gracefully shutdown server.
        tokio::spawn(signal::graceful_shutdown(handle.clone()));

        // Spawn a task to check wan address.
        tokio::spawn(check_wan_address());

        // http server tcp keepalive
        let tcp_keepalive = if self.0.no_keepalive {
            None
        } else {
            Some(Duration::from_secs(self.0.tcp_keepalive as u64 + 1))
        };

        // http server config
        let http_config = HttpConfig::new()
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .http2_keep_alive_interval(tcp_keepalive)
            .build();

        // http server incoming config
        let incoming_config = AddrIncomingConfig::new()
            .tcp_sleep_on_accept_errors(true)
            .tcp_keepalive(tcp_keepalive)
            .build();

        // http server mitm signal
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);

        // PreAuth mitm proxy
        #[cfg(feature = "preauth")]
        if let Some(pbind) = self.0.pbind.clone() {
            let builder = mitm::Builder::builder()
                .bind(pbind)
                .upstream_proxy(self.0.pupstream.clone())
                .cert(self.0.pcert.clone())
                .key(self.0.pkey.clone())
                .graceful_shutdown(rx)
                .cerificate_cache_size(1_000)
                .mitm_filters(vec![String::from("ios.chat.openai.com")])
                .handler(preauth::PreAuthHanlder)
                .build();
            if let Some(err) = builder.proxy().await.err() {
                warn!("PreAuth proxy error: {}", err);
            }
        }

        // Run http server
        let result = match (self.0.tls_cert, self.0.tls_key) {
            (Some(cert), Some(key)) => {
                let tls_config = RustlsConfig::from_pem_file(cert, key)
                    .await
                    .expect("Failed to load TLS keypair");

                axum_server::bind_rustls(self.0.bind.unwrap(), tls_config)
                    .handle(handle)
                    .addr_incoming_config(incoming_config)
                    .http_config(http_config)
                    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                    .await
            }
            _ => {
                axum_server::bind(self.0.bind.unwrap())
                    .handle(handle)
                    .addr_incoming_config(incoming_config)
                    .http_config(http_config)
                    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                    .await
            }
        };

        if let Some(err) = result.err() {
            warn!("Http Server error: {}", err);
        }

        if let Some(err) = tx.send(()).await.err() {
            warn!("Send shutdown signal error: {}", err);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok(())
    }
}

/// GET /auth/refresh_session
async fn get_session(jar: CookieJar) -> Result<impl IntoResponse, ResponseError> {
    let session = jar.get(API_AUTH_SESSION_COOKIE_KEY).ok_or_else(|| {
        ResponseError::Unauthorized(ProxyError::SessionRequired(API_AUTH_SESSION_COOKIE_KEY))
    })?;

    let session_token = with_context!(auth_client)
        .do_session(session.value())
        .await
        .map_err(ResponseError::BadRequest)?;

    match session_token {
        AccessToken::Session(session_token) => {
            let resp: Response<Body> = session_token.try_into()?;
            Ok(resp.into_response())
        }
        _ => Err(ResponseError::InternalServerError(
            ProxyError::SessionNotFound,
        )),
    }
}

/// POST /auth/token
async fn post_access_token(
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    account: axum::Form<AuthAccount>,
) -> Result<impl IntoResponse, ResponseError> {
    // check username/email in whitelist
    whitelist::check_whitelist(&account.username)?;

    if let Some(auth_key) = with_context!(auth_key) {
        // check bearer token exist
        let bearer = bearer.ok_or(ResponseError::Unauthorized(ProxyError::AuthKeyRequired))?;
        if auth_key.ne(bearer.token()) {
            return Err(ResponseError::Forbidden(ProxyError::AuthKeyError));
        }
    }

    if let Some(refresh_cookie_value) = &account.refresh_cookie {
        let session_token = with_context!(auth_client)
        .do_session(refresh_cookie_value.as_str())
        .await
        .map_err(ResponseError::BadRequest)?;

        match session_token {
            AccessToken::Session(session_token) => {
                let resp: Response<Body> = session_token.try_into()?;
                Ok(resp.into_response())
            }
            _ => Err(ResponseError::InternalServerError(
                ProxyError::SessionNotFound,
            )),
        }
    }else {
        
            match with_context!(auth_client).do_access_token(&account).await? {
                AccessToken::Session(session_token) => {
                    let resp: Response<Body> = session_token.try_into()?;
                    Ok(resp.into_response())
                }
                AccessToken::OAuth(c) => Ok(Json(AccessToken::OAuth(c)).into_response()),
            }
        
    }
  
}

/// POST /auth/refresh_token
async fn post_refresh_token(
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<RefreshToken>, ResponseError> {
    match with_context!(auth_client)
        .do_refresh_token(bearer.token())
        .await
    {
        Ok(refresh_token) => Ok(Json(refresh_token)),
        Err(err) => Err(ResponseError::BadRequest(err)),
    }
}

/// POST /auth/revoke_token
async fn post_revoke_token(
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
) -> Result<StatusCode, ResponseError> {
    match with_context!(auth_client)
        .do_revoke_token(bearer.token())
        .await
    {
        Ok(_) => Ok(StatusCode::OK),
        Err(err) => Err(ResponseError::BadRequest(err)),
    }
}

/// match path /dashboard/{tail.*}
/// POST https://api.openai.com/dashboard/onboarding/login"
/// POST https://api.openai.com/dashboard/user/api_keys
/// GET https://api.openai.com/dashboard/user/api_keys
/// POST https://api.openai.com/dashboard/billing/usage
/// POST https://api.openai.com/dashboard/billing/credit_grants
///
/// platform API match path /v1/{tail.*}
/// reference: https://platform.openai.com/docs/api-reference
async fn official_proxy(req: RequestExt) -> Result<impl IntoResponse, ResponseError> {
    let resp = with_context!(api_client)
        .send_request(URL_PLATFORM_API, req)
        .await?;
    response_convert(resp).await
}

/// reference: doc/http.rest
async fn unofficial_proxy(req: RequestExt) -> Result<impl IntoResponse, ResponseError> {
    let resp = with_context!(api_client)
        .send_request(URL_CHATGPT_API, req)
        .await?;
    response_convert(resp).await
}

impl TryInto<Response<Body>> for SessionAccessToken {
    type Error = ResponseError;

    fn try_into(self) -> Result<Response<Body>, Self::Error> {
        let session = self
            .session_token
            .clone()
            .ok_or(ResponseError::InternalServerError(
                ProxyError::SessionNotFound,
            ))?;

        let timestamp_secs = session
            .expires
            .unwrap_or_else(|| SystemTime::now())
            .duration_since(UNIX_EPOCH)
            .map_err(ResponseError::InternalServerError)?
            .as_secs_f64();

        let cookie = cookie::Cookie::build(API_AUTH_SESSION_COOKIE_KEY, session.value)
            .path("/")
            .expires(time::OffsetDateTime::from_unix_timestamp(
                timestamp_secs as i64,
            )?)
            .same_site(cookie::SameSite::Lax)
            .secure(true)
            .http_only(false)
            .finish();

        Ok(Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(header::SET_COOKIE, cookie.to_string())
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(serde_json::to_string(&self)?))
            .map_err(ResponseError::InternalServerError)?)
    }
}

async fn check_wan_address() {
    match with_context!(api_client)
        .get("https://ifconfig.me")
        .timeout(Duration::from_secs(70))
        .header(header::ACCEPT, mime::APPLICATION_JSON.as_ref())
        .send()
        .await
    {
        Ok(resp) => match resp.text().await {
            Ok(res) => {
                info!("What is my IP address: {}", res.trim())
            }
            Err(err) => {
                warn!("Check IP address error: {}", err.to_string())
            }
        },
        Err(err) => {
            warn!("Check IP request error: {}", err)
        }
    }
}
