use std::collections::HashMap;

use failure::Error;
use openidconnect::{
    core,
    EndUserName, EndUserUsername, LanguageTag, StandardClaims,
};
use rocket::{
    http::Status,
    request::{self, FromRequest, Request},
    Outcome, State,
};

use crate::application::{OidcApplication, OidcSessionCookie};

pub struct OidcUser {
    pub preferred_username: Option<EndUserUsername>,
    pub name: Option<HashMap<Option<LanguageTag>, EndUserName>>,
}

impl OidcUser {
    fn load_from_session(
        oidc: &OidcApplication,
        oidc_session: &OidcSessionCookie
    ) -> Result<OidcUser, Error> {
        let id_token_verifier: core::CoreIdTokenVerifier = oidc.client.id_token_verifier()?;
        let id_token_claims = oidc_session.id_token.claims(&id_token_verifier, &oidc.nonce)?;

        let preferred_username = id_token_claims.preferred_username().cloned();
        let name = id_token_claims.name().cloned();

        Ok(OidcUser { preferred_username, name })
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for OidcUser {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<OidcUser, ()> {
        if let Some(serialized_session) = request.cookies().get_private("oidc_user_session") {
            if let Ok(oidc_session) = serde_json::from_str::<OidcSessionCookie>(serialized_session.value()) {
                let oidc = request.guard::<State<OidcApplication>>()?;

                match OidcUser::load_from_session(&oidc, &oidc_session) {
                    Ok(user) => Outcome::Success(user),
                    Err(_) => {
                        request.cookies().remove_private(serialized_session);
                        Outcome::Failure((Status::UnprocessableEntity, ()))
                    }
                }
            } else {
                request.cookies().remove_private(serialized_session);
                Outcome::Forward(())
            }
        } else {
            Outcome::Forward(())
        }
    }
}
