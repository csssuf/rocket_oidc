use failure::Error;
use oauth2::{
    prelude::*,
    AuthorizationCode,
};
use rocket::{
    http::{Cookie, Cookies},
    response::Redirect,
    State,
};

use crate::application::{OidcApplication, OidcSessionCookie};

// TODO(csssuf): determine optional fields, etc.
#[derive(FromForm)]
pub(crate) struct OidcParams {
    code: String,
    state: String,
    session_state: String,
}

#[get("/oidc_redirect?<params>")]
pub(crate) fn oidc_redirect(mut cookies: Cookies, oidc: State<OidcApplication>, params: OidcParams) -> Result<Redirect, Error> {
    let code = AuthorizationCode::new(params.code);
    let token_response = oidc.client.exchange_code(code)?;

    let cookie = OidcSessionCookie {
        access_token: token_response.access_token().clone(),
        id_token: token_response.extra_fields().id_token().clone(),
    };

    cookies.add_private(Cookie::new("oidc_user_session", serde_json::to_string(&cookie)?));

    match cookies.get_private("oidc_redirect_destination") {
        Some(redirect_destination) => {
            cookies.remove_private(Cookie::named("oidc_redirect_destination"));
            Ok(Redirect::to(redirect_destination.value()))
        }
        None => Ok(Redirect::to("/")),
    }
}

#[get("/oidc_goto_auth")]
pub(crate) fn oidc_goto_auth(oidc: State<OidcApplication>) -> Redirect {
    Redirect::to(oidc.authorize_url.as_str())
}
