#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]

//! OpenID Connect support for Rocket via a request guard.
//!
//! It can be used simply by instantiating an [`OidcApplication`], invoking `attach` with your
//! `OidcApplication` and `Rocket` instances, and adding the [`OidcUser`] guard to any requests
//! which should be protected via OpenID Connect authentication:
//!
//! ```no_run
//! #![feature(plugin, custom_derive)]
//! #![plugin(rocket_codegen)]
//!
//! use oauth2::prelude::*;
//! use oauth2::{ClientId, ClientSecret};
//! use openidconnect::IssuerUrl;
//! use rocket::{
//!     http::{Cookie, Cookies},
//!     response::Redirect,
//! };
//! use rocket_oidc::{OidcApplication, OidcUser};
//! use url::Url;
//!
//! #[get("/")]
//! fn authed_user(user: OidcUser) -> String {
//!     format!("Hello, {}!", user.name().unwrap_or_else(|| "nameless user".to_string()))
//! }
//!
//! #[get("/", rank = 2)]
//! fn user() -> Redirect {
//!     Redirect::to("/oidc_goto_auth")
//! }
//!
//! fn main() {
//!     let issuer_url = IssuerUrl::new("https://oidc.endpoint.here/".to_string()).unwrap();
//!     let client_id = ClientId::new("client-id".to_string());
//!     let client_secret = ClientSecret::new("YOUR_CLIENT_SECRET".to_string());
//!
//!     let oidc = OidcApplication::new(
//!         Url::parse("http://your.application.host/").unwrap(),
//!         issuer_url,
//!         client_id,
//!         client_secret,
//!     ).unwrap();
//!
//!     rocket_oidc::attach(rocket::ignite(), oidc)
//!         .mount("/", routes![authed_user, user])
//!         .launch();
//! }
//! ```
//!
//! This example includes the necessary second route for redirecting unauthenticated requests to
//! authenticate with the OpenID Connect provider. Redirecting to `/oidc_goto_auth` is sufficient
//! to return users to the original requested route upon successfully authenticating.
//!
//! [`OidcApplication`]: struct.OidcApplication.html
//! [`OidcUser`]: struct.OidcUser.html

use rocket::Rocket;

mod application;
mod guard;
mod routes;

pub use crate::{
    application::OidcApplication,
    guard::OidcUser,
};

/// Attach the given `OidcApplication` to the provided `Rocket` instance.
///
/// In addition to attaching the `OidcApplication` as a piece of `State`, this function also adds
/// the routes used internally by `rocket_oidc` for redirecting to the OpenID Connect provider and
/// post-authentication redirection.
pub fn attach(rocket: Rocket, oidc: OidcApplication) -> Rocket {
    rocket.manage(oidc).mount("/", routes![routes::oidc_redirect, routes::oidc_goto_auth])
}
