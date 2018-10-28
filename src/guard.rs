use std::collections::HashMap;

use failure::Error;
use openidconnect::{
    core,
    EndUserName, EndUserUsername, LanguageTag, StandardClaims,
};
use rocket::{
    http::{Cookie, Status},
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

    pub fn name(&self) -> Option<String> {
        match &self.name {
            Some(name_map) => name_map.get(&None).map(|name| name.as_str().to_owned()),
            None => None
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for OidcUser {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<OidcUser, ()> {
        let mut cookies = request.cookies();

        if let Some(serialized_session) = cookies.get_private("oidc_user_session") {
            if let Ok(oidc_session) = serde_json::from_str::<OidcSessionCookie>(serialized_session.value()) {
                let oidc = request.guard::<State<OidcApplication>>()?;

                match OidcUser::load_from_session(&oidc, &oidc_session) {
                    Ok(user) => Outcome::Success(user),
                    Err(_) => {
                        cookies.remove_private(serialized_session);
                        Outcome::Failure((Status::UnprocessableEntity, ()))
                    }
                }
            } else {
                cookies.remove_private(serialized_session);
                cookies.add_private(Cookie::new(
                    "oidc_redirect_destination",
                    request.uri().to_string(),
                ));
                Outcome::Forward(())
            }
        } else {
            cookies.add_private(Cookie::new(
                "oidc_redirect_destination",
                request.uri().to_string(),
            ));
            Outcome::Forward(())
        }
    }
}
