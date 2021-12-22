use failure::Error;
use openidconnect::{
    core,
    EndUserName, EndUserUsername, LocalizedClaim,
};
use rocket::{
    http::{Cookie, Status, SameSite},
    request::{self, FromRequest, Request, Outcome},
};

use crate::application::{OidcApplication, OidcSessionCookie};

/// Rocket request guard for OpenID Connect authentication.
///
/// Provides basic information about the authenticated user. This guard can be used as a building
/// block for more complex request guards requiring authorization information provided by OpenID
/// Connect.
pub struct OidcUser {
    pub preferred_username: Option<EndUserUsername>,
    pub name: Option<LocalizedClaim<EndUserName>>,
}

impl OidcUser {
    fn load_from_session(
        oidc: &OidcApplication,
        oidc_session: &OidcSessionCookie
    ) -> Result<OidcUser, Error> {
        let id_token_verifier: core::CoreIdTokenVerifier = oidc.client.id_token_verifier();
        let id_token_claims = oidc_session.id_token.claims(&id_token_verifier, &oidc.nonce)?;

        let preferred_username = id_token_claims.preferred_username().cloned();
        let name = id_token_claims.name().cloned();

        Ok(OidcUser { preferred_username, name })
    }

    /// Retrieve the default-language name for this user.
    ///
    /// OpenID Connect provides a mapping of language to full name for users; while comprehensive,
    /// this approach can be overly complicated for many applications. This function provides
    /// simpler access to the `None`-language name.
    pub fn name(&self) -> Option<String> {
        match &self.name {
            Some(name_map) => name_map.get(None).map(|name| name.as_str().to_owned()),
            None => None
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OidcUser {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let cookies = request.cookies();

        if let Some(serialized_session) = cookies.get_private("oidc_user_session") {
            if let Ok(oidc_session) = serde_json::from_str::<OidcSessionCookie>(serialized_session.value()) {
                let oidc = request.rocket().state::<OidcApplication>();
                if let Some(oidc) = oidc{
                    match OidcUser::load_from_session(&oidc, &oidc_session) {
                        Ok(user) => Outcome::Success(user),
                        Err(_) => {
                            cookies.remove_private(serialized_session);
                            Outcome::Failure((Status::UnprocessableEntity, ()))
                        }
                    }
                }else{
                    Outcome::Forward(())
                }
            } else {
                cookies.remove_private(serialized_session);
                cookies.add_private(Cookie::build("oidc_redirect_destination", request.uri().to_string()).same_site(SameSite::Lax).finish());
                
                Outcome::Forward(())
            }
        } else {
            cookies.add_private(Cookie::build("oidc_redirect_destination", request.uri().to_string()).same_site(SameSite::Lax).finish());

            Outcome::Forward(())
        }
    }
}
