use ffi::sec::SECStatus;
use libc::c_char;

#[link(name="nss3")]
extern "C"
{
    pub fn NSS_NoDB_Init(reserved: *mut c_char) -> SECStatus;
    pub fn NSS_Shutdown() -> SECStatus;
}
