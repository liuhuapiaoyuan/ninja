use crate::serve::error::{ProxyError, ResponseError};
use axum::{
    extract::{ConnectInfo, State},
    http::Request,
    middleware::Next,
    response::Response,
};

use super::tokenbucket::{TokenBucket, TokenBucketProvider};

pub(crate) async fn limit_middleware<B>(
    State(limit): State<std::sync::Arc<TokenBucketProvider>>,
    ConnectInfo(socket_addr): ConnectInfo<std::net::SocketAddr>,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, ResponseError> {
    let addr = socket_addr.ip();
    match limit.acquire(addr) {
        Ok(condition) => match condition {
            true => Ok(next.run(request).await),
            false => Err(ResponseError::TooManyRequests(ProxyError::TooManyRequests)),
        },
        Err(err) => Err(ResponseError::BadGateway(err)),
    }
}
