use super::STATIC_FILES;
use crate::arkose::ArkoseToken;
use crate::arkose::Type;
use crate::context::args::Args;
use crate::serve::error::ResponseError;
use crate::warn;
use crate::with_context;
use axum::body::Body;
use axum::http::header;
use axum::http::method::Method;
use axum::http::response::Builder;
use axum::http::Response;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{
    http::{HeaderMap, Uri},
    routing::any,
    Form, Router,
};
use bytes::Bytes;
use std::collections::HashMap;

pub(super) fn config(router: Router, args: &Args) -> Router {
    if args.arkose_endpoint.is_none() {
        return router
            .route("/cdn/*path", any(proxy))
            .route("/v2/*path", any(proxy))
            .route("/fc/*path", any(proxy));
    }
    router
}

async fn proxy(
    uri: Uri,
    method: Method,
    mut headers: HeaderMap,
    body: Option<Form<HashMap<String, String>>>,
) -> Result<impl IntoResponse, ResponseError> {
    let req_path = uri.path();

    if let Some((_, v)) = STATIC_FILES
        .get()
        .expect("static file")
        .iter()
        .find(|(k, _v)| k.contains(req_path))
    {
        let mime_type = if v.mime_type.eq(mime::APPLICATION_OCTET_STREAM.as_ref()) {
            mime::TEXT_HTML.as_ref()
        } else {
            v.mime_type
        };
        return create_response(StatusCode::OK, mime_type, v.data);
    }

    if req_path.contains("/fc/gt2/public_key/") {
        let pk = req_path.trim_start_matches("/fc/gt2/public_key/");
        match ArkoseToken::new_from_context(Type::from_pk(pk)?).await {
            Ok(arkose_token) => {
                if arkose_token.success() {
                    let target = serde_json::json!({
                        "token": arkose_token,
                        "challenge_url":"",
                        "challenge_url_cdn":"https://client-api.arkoselabs.com/cdn/fc/assets/ec-game-core/bootstrap/1.17.1/standard/game_core_bootstrap.js",
                        "challenge_url_cdn_sri":null,
                        "noscript":"Disable",
                        "inject_script_integrity":null,
                        "inject_script_url":null,
                        "mbio":true,
                        "tbio":true,
                        "kbio":true,
                        "styles":null,
                        "iframe_width":null,
                        "iframe_height":null,
                        "disable_default_styling":false,
                        "string_table":{
                            "meta.api_timeout_error":"与验证服务器的连接已中断。请重新加载挑战以重试。",
                            "meta.generic_error":"出错了。请重新加载挑战以重试。",
                            "meta.loading_info":"进行中，请稍候...",
                            "meta.reload_challenge":"重新加载挑战",
                            "meta.visual_challenge_frame_title":"视觉挑战"
                        }
                    });
                    return create_response(
                        StatusCode::OK,
                        mime::APPLICATION_JSON.as_ref(),
                        target.to_string(),
                    );
                }
            }
            Err(err) => {
                warn!("ArkoseToken::new_from_context error: {}", err);
            }
        }
    }

    for header in &[
        header::CONNECTION,
        header::CONTENT_TYPE,
        header::CONTENT_LENGTH,
    ] {
        headers.remove(header);
    }

    let client = with_context!(api_client);
    let url = format!("https://client-api.arkoselabs.com{}", req_path);

    let resp = match body {
        Some(form) => {
            client
                .request(method, url)
                .headers(headers)
                .form(&form.0)
                .send()
                .await
        }
        None => client.request(method, url).headers(headers).send().await,
    }
    .map_err(ResponseError::InternalServerError)?;

    let mut builder = Response::builder().status(resp.status());
    for ele in resp.headers() {
        builder = builder.header(ele.0, ele.1);
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(ResponseError::InternalServerError)?;

    Ok(create_response_with_bytes(builder, bytes)?)
}

fn create_response(
    status: StatusCode,
    content_type: &str,
    data: impl Into<Body>,
) -> Result<Response<Body>, ResponseError> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(data.into())
        .map_err(ResponseError::InternalServerError)
}

fn create_response_with_bytes(
    builder: Builder,
    bytes: Bytes,
) -> Result<Response<Body>, ResponseError> {
    builder
        .body(Body::from(bytes))
        .map_err(ResponseError::InternalServerError)
}
