use oauth2::{
    AuthorizationCode,
};
use openidconnect::{
    OAuth2TokenResponse,
    TokenResponse
};
use rocket::{
    http::{
        Cookie, 
        CookieJar,
        Status,
        SameSite
    },
    response::{
        Redirect,
        status::Custom,
    },
    State,
    FromForm,
    get
};

use crate::application::{OidcApplication, OidcSessionCookie};

// TODO(csssuf): determine optional fields, etc.
#[derive(FromForm)]
pub(crate) struct OidcParams {
    code: String,
    state: String,
    session_state: String,
}

#[get("/oidc_redirect?<state>&<session_state>&<code>")]
pub(crate) async fn oidc_redirect(cookies: &CookieJar<'_>, oidc: &State<OidcApplication>, state: String, session_state: String, code:String) -> Result<Redirect, Custom<String>> {
    let params = OidcParams{
        code,
        state,
        session_state
    };

    let code = AuthorizationCode::new(params.code);
    let token_response = oidc.client.exchange_code(code).request_async(oauth2::reqwest::async_http_client).await
        .map_err(|_|Custom(Status::InternalServerError, "Could not get Token response".to_string()))?;

    let access_token = token_response.access_token();
    let id_token = token_response.id_token();

    if let Some(id_token) = id_token{
        let cookie = OidcSessionCookie {
            access_token: access_token.clone(),
            id_token: id_token.clone(),
        };

        let serialized_cookie = serde_json::to_string(&cookie)
            .map_err(|_|Custom(Status::InternalServerError, "Could not set Cookie".to_string()))?;
    
        cookies.add_private(Cookie::build("oidc_user_session", serialized_cookie).same_site(SameSite::Lax).finish());

        if let Some(redirect_destination)  = cookies.get_private("oidc_redirect_destination"){
            cookies.remove_private(Cookie::named("oidc_redirect_destination"));
            return Ok(Redirect::to(redirect_destination.value().to_string()));
        }
    }
    
    Ok(Redirect::to("/"))
}

#[get("/oidc_goto_auth")]
pub(crate) fn oidc_goto_auth(oidc: &State<OidcApplication>) -> Redirect {
    Redirect::to(oidc.authorize_url.to_string())
}
