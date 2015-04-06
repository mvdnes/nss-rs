extern crate libc;

pub use nss::{init, close};

mod ffi;
mod nss;
pub mod crypto;
pub mod result;
