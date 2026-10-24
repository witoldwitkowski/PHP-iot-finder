//! The optional local web GUI: `iotscan gui`.
//!
//! A tiny HTTP server bound to 127.0.0.1 that serves one embedded single-page
//! app and a JSON API. Defences, because a local web server is still a web server:
//!
//! * loopback only; random port unless given,
//! * a 128-bit random token (in the URL printed to the terminal, then a
//!   `HttpOnly; SameSite=Strict` cookie) required for every request,
//! * `Host` must be `127.0.0.1:<port>` or `localhost:<port>` (DNS-rebinding),
//! * state-changing requests need `Content-Type: application/json` and a
//!   same-origin `Origin` (CSRF),
//! * strict CSP, `nosniff`, `no-referrer`, `no-store`, frame denial,
//! * bounded request sizes, timeouts and connection count,
//! * the front-end never uses `innerHTML`, so device-supplied text cannot inject markup.

pub mod api;
pub mod server;

pub use server::{Server, serve};
