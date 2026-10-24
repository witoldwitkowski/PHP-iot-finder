//! iotscan: a safe, extensible vulnerability scanner for home IoT networks.
#![deny(unsafe_code)]

pub mod advisories;
pub mod allowlist;
pub mod app;
pub mod caps;
pub mod checkers;
pub mod cli;
pub mod demo;
pub mod diff;
pub mod discovery;
pub mod dns;
pub mod engine;
pub mod fingerprint;
pub mod gui;
pub mod history;
pub mod http;
pub mod limits;
pub mod model;
pub mod oui;
pub mod paths;
pub mod ports;
pub mod privsep;
pub mod progress;
pub mod report;
pub mod scope;
pub mod selftest;
pub mod sys;
pub mod testkit;
pub mod tlsconf;
pub mod util;
pub mod version;
