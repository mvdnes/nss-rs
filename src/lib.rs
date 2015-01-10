#![feature(unsafe_destructor)]
#![cfg_attr(test, allow(unstable))]

#[allow(unstable)]
extern crate libc;

#[macro_use]
extern crate log;

pub use nss::{init, close};

mod ffi;
mod nss;
pub mod crypto;
pub mod result;
