# rocket\_oidc

OpenID Connect support for Rocket.

## Example usage

```rust
use oauth2::{ClientId, ClientSecret};
use openidconnect::IssuerUrl;
#[macro_use] extern crate rocket;
use rocket::{
    response::Redirect,
    routes,
    get
};
use rocket_oidc::{OidcApplication, OidcUser};

use url::Url;

#[get("/")]
fn authed_user(user: OidcUser) -> String {
    format!("Hello, {}!", user.name().unwrap_or("nameless user".to_string()))
}

#[get("/", rank = 2)]
fn user() -> Redirect {
    Redirect::to("/oidc_goto_auth")
}

#[launch]
fn rocket() -> _ {
    let issuer_url = IssuerUrl::new("https://oidc.endpoint.here/".to_string()).unwrap();
    let client_id = ClientId::new("client-id".to_string());
    let client_secret = ClientSecret::new("YOUR_CLIENT_SECRET".to_string());

    let oidc = OidcApplication::new(
        Url::parse("http://your.application.host/").unwrap(),
        issuer_url,
        client_id,
        client_secret,
    ).unwrap();

    rocket::build()
        .manage(oidc)                           //Add State
        .mount("/", rocket_oidc::routes())      //Add Routes
        .mount("/", routes![authed_user, user])
}
```
