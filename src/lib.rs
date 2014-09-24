#![feature(phase)]

extern crate libc;
#[phase(plugin, link)] extern crate log;

pub use nss::{init, close};

mod ffi;
mod nss;
pub mod crypto;
