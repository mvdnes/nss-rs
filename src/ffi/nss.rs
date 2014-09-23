use libc::c_char;

#[repr(C)]
pub enum SECStatus
{
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0
}

#[link(name="nss3")]
extern "C"
{
    pub fn NSS_NoDB_Init(reserved: *mut c_char) -> SECStatus;
    pub fn NSS_Shutdown() -> SECStatus;
}
