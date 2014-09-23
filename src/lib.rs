#![feature(phase)]

extern crate libc;
#[phase(plugin, link)] extern crate log;

pub use nss::{init, close};

mod ffi
{
    pub mod nspr;
    pub mod nss;
    pub mod pk11;
    pub mod sec;
}
mod nss;
pub mod crypto;
