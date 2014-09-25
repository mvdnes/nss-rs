#![feature(phase)]
#![feature(macro_rules)]

extern crate sync;
extern crate libc;
#[phase(plugin, link)] extern crate log;

pub use nss::{init, close};

pub type NSSError = ffi::nspr::PRError;
pub type NSSResult<T> = Result<T, NSSError>;

mod ffi;
mod nss;
mod util;
pub mod crypto;
