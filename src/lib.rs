#![feature(phase)]

extern crate libc;
#[phase(plugin, link)] extern crate log;

mod ffi
{
    pub mod nspr;
    pub mod nss;
}
pub mod nss;
