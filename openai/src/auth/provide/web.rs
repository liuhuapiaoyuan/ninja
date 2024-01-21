use super::{
    AuthProvider, AuthResult, AuthenticateMfaData, GetAuthorizedUrlData, IdentifierData,
    RequestContext, RequestContextExt,
};
use crate::auth::error::AuthError;
use crate::auth::{
    model::{self, AuthStrategy},
    provide::AuthenticateData,
    AuthClient, OPENAI_OAUTH_URL,
};
use crate::constant::API_AUTH_SESSION_COOKIE_KEY;
use crate::{debug, warn, URL_CHATGPT_API};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use url::Url;

pub(crate) struct WebAuthProvider(pub(crate) Client);

impl WebAuthProvider {
    pub fn new(inner: Client) -> impl AuthProvider + Send + Sync {
        Self(inner)
    }

    async fn csrf_token(&self, ctx: &mut RequestContext<'_>) -> AuthResult<()> {
        let resp = self
            .0
            .get(format!("{URL_CHATGPT_API}/api/auth/csrf"))
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        match resp.error_for_status() {
            Ok(resp) => {
                let res = resp.json::<Value>().await?;
                let csrf_token = res
                    .as_object()
                    .and_then(|obj| obj.get("csrfToken"))
                    .and_then(|csrf| csrf.as_str())
                    .ok_or(AuthError::FailedCsrfToken)?;
                ctx.set_csrf_token(csrf_token);
                return Ok(());
            }
            Err(err) => {
                warn!("{err}");
                Err(AuthError::FailedCsrfToken)
            }
        }
    }

    async fn authorized(&self, ctx: &mut RequestContext<'_>) -> AuthResult<()> {
        let resp = self
            .0
            .post(format!(
                "{URL_CHATGPT_API}/api/auth/signin/auth0?prompt=login"
            ))
            .ext_context(ctx)
            .form(
                &GetAuthorizedUrlData::builder()
                    .callback_url("/")
                    .csrf_token(&ctx.csrf_token)
                    .json("true")
                    .build(),
            )
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        match resp.error_for_status() {
            Ok(resp) => {
                let res = resp.json::<Value>().await?;
                let url = res
                    .as_object()
                    .and_then(|v| v.get("url"))
                    .and_then(|v| v.as_str())
                    .ok_or(AuthError::FailedAuthorizedUrl)?;
                return self.state(url, ctx).await;
            }
            Err(err) => {
                debug!("WebAuthHandle authorized url error: {err}");
                Err(AuthError::FailedAuthorizedUrl)
            }
        }
    }

    async fn state(&self, url: &str, ctx: &mut RequestContext<'_>) -> AuthResult<()> {
        let resp = self
            .0
            .get(url)
            .ext_context(ctx)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        let locatio = AuthClient::get_location_path(resp.headers())?;
        let resp = self
            .0
            .get(format!("{OPENAI_OAUTH_URL}{locatio}"))
            .ext_context(ctx)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        let state = AuthClient::get_callback_state(&resp.url());
        ctx.set_state(state.as_str());

        Ok(AuthClient::response_handle_unit(resp)
            .await
            .map_err(|_| AuthError::FailedState)?)
    }

    async fn authenticate_username(&self, ctx: &mut RequestContext<'_>) -> AuthResult<()> {
        let url = format!("{OPENAI_OAUTH_URL}/u/login/identifier?state={}", ctx.state);
        let resp = self
            .0
            .post(&url)
            .ext_context(ctx)
            .form(
                &IdentifierData::builder()
                    .action("default")
                    .state(&ctx.state)
                    .username(&ctx.account.username)
                    .js_available(true)
                    .webauthn_available(true)
                    .is_brave(false)
                    .webauthn_platform_available(false)
                    .build(),
            )
            .send()
            .await?
            .ext_context(ctx);

        AuthClient::response_handle_unit(resp)
            .await
            .map_err(|_| AuthError::InvalidEmail)
    }

    async fn authenticate_password(
        &self,
        ctx: &mut RequestContext<'_>,
    ) -> AuthResult<model::AccessToken> {
        ctx.load_arkose_token().await?;

        let resp = self
            .0
            .post(format!(
                "{OPENAI_OAUTH_URL}/u/login/password?state={}",
                ctx.state
            ))
            .ext_context(ctx)
            .form(
                &AuthenticateData::builder()
                    .action("default")
                    .state(&ctx.state)
                    .username(&ctx.account.username)
                    .password(&ctx.account.password)
                    .build(),
            )
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        // If resp status is client error return InvalidEmailOrPassword
        if resp.status().is_client_error() {
            return Err(AuthError::InvalidEmailOrPassword);
        }

        if resp.status().is_redirection() {
            let location = AuthClient::get_location_path(&resp.headers())?;
            if location.contains("https://chat.openai.com/") {
                warn!("WebAuthProvider::authenticate_password: invalid location path: {location}");
                return Err(AuthError::InvalidLocationPath);
            }

            let resp = self
                .0
                .get(format!("{OPENAI_OAUTH_URL}{location}"))
                .ext_context(ctx)
                .send()
                .await
                .map_err(AuthError::FailedRequest)?
                .ext_context(ctx);

            if resp.status().is_redirection() {
                let location = AuthClient::get_location_path(resp.headers())?;
                if location.starts_with("/u/mfa-otp-challenge") {
                    let mfa = ctx.account.mfa.clone().ok_or(AuthError::MFARequired)?;
                    return self.authenticate_mfa(ctx, &mfa, location).await;
                }

                let resp = self
                    .0
                    .get(location)
                    .ext_context(ctx)
                    .send()
                    .await
                    .map_err(AuthError::FailedRequest)?
                    .ext_context(ctx);

                return match resp.status() {
                    StatusCode::FOUND => self.get_access_token(ctx).await,
                    _ => Err(AuthError::InvalidEmailOrPassword),
                };
            }
        }
        Err(AuthError::FailedLogin)
    }

    async fn authenticate_mfa(
        &self,
        ctx: &mut RequestContext<'_>,
        mfa_code: &str,
        location: &str,
    ) -> AuthResult<model::AccessToken> {
        // Parse location
        let url = Url::parse(&format!("{OPENAI_OAUTH_URL}{}", location))
            .map_err(AuthError::InvalidLoginUrl)?;

        // Get state from url
        let state = AuthClient::get_callback_state(&url);

        let data = AuthenticateMfaData::builder()
            .action("default")
            .state(&state)
            .code(mfa_code)
            .build();

        let resp = self
            .0
            .post(url)
            .ext_context(ctx)
            .json(&data)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?
            .ext_context(ctx);

        let location = AuthClient::get_location_path(resp.headers())?;

        // If location path starts with /authorize/resume? and mfa is none return MFAFailed
        if location.starts_with("/authorize/resume?") && ctx.account.mfa.is_none() {
            return Err(AuthError::MFAFailed);
        }

        self.get_access_token(ctx).await
    }

    async fn get_access_token(
        &self,
        ctx: &mut RequestContext<'_>,
    ) -> AuthResult<model::AccessToken> {
        let resp = self
            .0
            .get(format!("{URL_CHATGPT_API}/api/auth/session"))
            .ext_context(ctx)
            .send()
            .await
            .map_err(AuthError::FailedRequest)?;

        match resp.error_for_status() {
            Ok(resp) => {
                let session = resp
                    .cookies()
                    .find(|c| c.name().eq(API_AUTH_SESSION_COOKIE_KEY))
                    .map(|c| model::Session {
                        value: c.value().to_owned(),
                        expires: c.expires(),
                    });

                match session {
                    Some(session) => {
                        let mut session_access_token = resp
                            .json::<model::SessionAccessToken>()
                            .await
                            .map_err(AuthError::DeserializeError)?;
                        session_access_token.session_token = Some(session.clone());
                        session_access_token.refresh_cookie = Some(session);
                        Ok(model::AccessToken::Session(session_access_token))
                    }
                    None => {
                        let text = resp.text().await?;
                        warn!("Unable to obtain {API_AUTH_SESSION_COOKIE_KEY}, error: {text}");
                        Err(AuthError::FailedAccessToken(text))
                    }
                }
            }
            Err(err) => Err(AuthClient::handle_error(err)),
        }
    }
}

#[async_trait::async_trait]
impl AuthProvider for WebAuthProvider {
    fn supports(&self, t: &AuthStrategy) -> bool {
        t.eq(&AuthStrategy::Web)
    }

    async fn do_access_token(
        &self,
        account: &model::AuthAccount,
    ) -> AuthResult<model::AccessToken> {
        let mut ctx = RequestContext::new(account);
        // csrf token
        self.csrf_token(&mut ctx).await?;

        // authorized
        self.authorized(&mut ctx).await?;

        // check username
        self.authenticate_username(&mut ctx).await?;

        // check password and username
        self.authenticate_password(&mut ctx).await
    }

    async fn do_refresh_token(&self, _refresh_token: &str) -> AuthResult<model::RefreshToken> {
        Err(AuthError::NotSupportedImplementation)
    }

    async fn do_revoke_token(&self, _refresh_token: &str) -> AuthResult<()> {
        Err(AuthError::NotSupportedImplementation)
    }
}
