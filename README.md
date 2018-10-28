# rocket\_oidc

OpenID Connect support for Rocket.

## Example usage

```rust
use oauth2::prelude::*;
use oauth2::{ClientId, ClientSecret};
use openidconnect::IssuerUrl;
use rocket::{
    http::{Cookie, Cookies},
    response::Redirect,
};
use rocket_oidc::{OidcApplication, OidcUser};
use url::Url;

#[get("/")]
fn authed_user(user: OidcUser) -> String {
    format!("Hello, {}!", user.name().unwrap_or_else("nameless user".to_string()))
}

#[get("/", rank = 2)]
fn user() -> Redirect {
    Redirect::to("/oidc_goto_auth")
}

fn main() {
    let issuer_url = IssuerUrl::new("https://oidc.endpoint.here/".to_string()).unwrap();
    let client_id = ClientId::new("client-id".to_string());
    let client_secret = ClientSecret::new("YOUR_CLIENT_SECRET".to_string());

    let oidc = OidcApplication::new(
        Url::parse("http://your.application.host/").unwrap(),
        issuer_url,
        client_id,
        client_secret,
    ).unwrap();

    rocket_oidc::attach(rocket::ignite(), oidc)
        .mount("/", routes![authed_user, user])
        .launch();
}
```
