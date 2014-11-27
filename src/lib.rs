#![feature(phase)]
#![feature(macro_rules)]
#![feature(unsafe_destructor)]

extern crate libc;
#[phase(plugin, link)] extern crate log;

pub use nss::{init, close};

mod ffi;
mod nss;
pub mod crypto;
pub mod result;
