use failure::Error;
use oauth2::{
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

/// State for an application utilizing OpenID Connect
///
/// This structure is mainly used internally by `rocket_oidc` to interface with the OpenID Connect
/// provider, and doesn't require usage beyond initial creation and attachment by consumers of
/// `rocket_oidc`.
pub struct OidcApplication {
    pub(crate) client: core::CoreClient,
    pub(crate) authorize_url: Url,
    pub(crate) csrf_state: CsrfToken,
    pub(crate) nonce: Nonce,
}

impl OidcApplication {
    /// Create a new OpenID Connect application from the provided components.
    ///
    /// `base_url` is the base URL of this application.
    /// `issuer` is the base URL of the OpenID Connect provider.
    /// `client_id` is the client ID provided to this application by the OpenID Connect provider.
    /// `client_secret` is the client secret provided to this application by the OpenID Connect
    /// provider.
    pub async fn new(
        base_url: Url,
        issuer: IssuerUrl,
        client_id: ClientId,
        client_secret: ClientSecret,
    ) -> Result<OidcApplication, Error> {
        let provider_metadata = core::CoreProviderMetadata::discover_async(issuer, oauth2::reqwest::async_http_client).await?;
        let client = core::CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            .set_redirect_uri(RedirectUrl::new(String::from(base_url.join("/oidc_redirect")?.as_str()))?);

        let (authorize_url, csrf_state, nonce) = client.authorize_url(
            AuthenticationFlow::<core::CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        ).url();

        Ok(OidcApplication { client, authorize_url, csrf_state, nonce })
    }
}
