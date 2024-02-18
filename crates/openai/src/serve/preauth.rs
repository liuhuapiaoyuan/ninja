use crate::with_context;
use axum_extra::extract::CookieJar;
use mitm::proxy::hyper::{
    body::Body,
    http::{HeaderMap, HeaderValue, Request, Response},
};
use mitm::proxy::{handler::HttpHandler, mitm::RequestOrResponse};
use std::fmt::Write;

#[derive(Clone)]
pub struct PreAuthHanlder;

impl HttpHandler for PreAuthHanlder {
    fn handle_request(&self, req: Request<Body>) -> RequestOrResponse {
        log_req(&req);
        collect_preauth_cookie(req.headers());
        RequestOrResponse::Request(req)
    }

    fn handle_response(&self, res: Response<Body>) -> Response<Body> {
        log_res(&res);
        collect_preauth_cookie(res.headers());
        res
    }
}

fn collect_preauth_cookie(headers: &HeaderMap<HeaderValue>) {
    let jar = CookieJar::from_headers(headers);
    for c in jar.iter() {
        // Preauth cookie max age
        if c.name().eq("_preauth_devicecheck") {
            let max_age = c.max_age().map(|a| a.as_seconds_f32() as u32);
            with_context!(push_preauth_cookie, c.value(), max_age);
        }
    }
}

pub fn log_req(req: &Request<Body>) {
    let headers = req.headers();
    let mut header_formated = String::new();
    for (key, value) in headers {
        let v = match value.to_str() {
            Ok(v) => v.to_string(),
            Err(_) => {
                format!("[u8]; {}", value.len())
            }
        };
        write!(
            &mut header_formated,
            "\t{:<20}{}\r\n",
            format!("{}:", key.as_str()),
            v
        )
        .unwrap();
    }

    tracing::debug!(
        "{} {}
Headers:
{}",
        req.method(),
        req.uri().to_string(),
        header_formated
    )
}

pub fn log_res(res: &Response<Body>) {
    let headers = res.headers();
    let mut header_formated = String::new();
    for (key, value) in headers {
        let v = match value.to_str() {
            Ok(v) => v.to_string(),
            Err(_) => {
                format!("[u8]; {}", value.len())
            }
        };
        write!(
            &mut header_formated,
            "\t{:<20}{}\r\n",
            format!("{}:", key.as_str()),
            v
        )
        .unwrap();
    }

    tracing::debug!(
        "{} {:?}
Headers:
{}",
        res.status(),
        res.version(),
        header_formated
    )
}
