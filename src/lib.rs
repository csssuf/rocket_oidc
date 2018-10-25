#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]

use rocket::Rocket;

mod application;
mod guard;
mod routes;

pub use crate::{
    application::OidcApplication,
    guard::OidcUser,
};

pub fn attach(rocket: Rocket, oidc: OidcApplication) -> Rocket {
    rocket.manage(oidc).mount("/", routes![routes::oidc_redirect, routes::oidc_goto_auth])
}
