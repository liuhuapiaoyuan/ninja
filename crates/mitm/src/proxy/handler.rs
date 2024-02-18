use hyper::{Body, Request, Response};
use std::sync::{Arc, RwLock};
use wildmatch::WildMatch;

use super::mitm::RequestOrResponse;

pub trait HttpHandler: Clone + Send + Sync + 'static {
    fn handle_request(&self, req: Request<Body>) -> RequestOrResponse {
        RequestOrResponse::Request(req)
    }

    fn handle_response(&self, res: Response<Body>) -> Response<Body> {
        res
    }
}

#[derive(Clone, Default)]
pub struct MitmFilter {
    filters: Arc<RwLock<Vec<WildMatch>>>,
}

impl MitmFilter {
    pub fn new(filters: Vec<String>) -> Self {
        let filters = filters.iter().map(|f| WildMatch::new(f)).collect();
        Self {
            filters: Arc::new(RwLock::new(filters)),
            ..Default::default()
        }
    }

    pub async fn filter_req(&self, req: &Request<Body>) -> bool {
        let host = req.uri().host().unwrap_or_default();
        let list = self.filters.read().unwrap();
        for m in list.iter() {
            if m.matches(host) {
                return true;
            }
        }
        false
    }

    pub async fn filter(&self, host: &str) -> bool {
        let list = self.filters.read().unwrap();
        for m in list.iter() {
            if m.matches(host) {
                return true;
            }
        }
        false
    }
}
