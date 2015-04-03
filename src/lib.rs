extern crate libc;
#[macro_use] extern crate log;

pub use nss::{init, close};

mod ffi;
mod nss;
pub mod crypto;
pub mod result;
