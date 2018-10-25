use failure::Error;
use oauth2::prelude::*;
use oauth2::{
    prelude::*,
    AccessToken, ClientId, ClientSecret, CsrfToken, RedirectUrl,
};
use openidconnect::{
    AuthenticationFlow, IssuerUrl, Nonce,
    core,
};
use serde_derive::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OidcSessionCookie {
    pub(crate) access_token: AccessToken,
    pub(crate) id_token: core::CoreIdToken,
}

pub struct OidcApplication {
    pub(crate) client: core::CoreClient,
    pub(crate) authorize_url: Url,
    pub(crate) csrf_state: CsrfToken,
    pub(crate) nonce: Nonce,
}

impl OidcApplication {
    pub fn new(
        base_url: Url,
        issuer: IssuerUrl,
        client_id: ClientId,
        client_secret: ClientSecret,
    ) -> Result<OidcApplication, Error> {
        let client = core::CoreClient::discover(client_id, Some(client_secret), &issuer)?
            .set_redirect_uri(RedirectUrl::new(base_url.join("/oidc_redirect")?));

        let (authorize_url, csrf_state, nonce) = client.authorize_url(
            &AuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );

        Ok(OidcApplication { client, authorize_url, csrf_state, nonce })
    }
}
