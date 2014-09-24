use ffi::nspr;
use libc::{c_uint, c_uchar};

#[must_use]
#[repr(C)]
pub enum SECStatus
{
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0
}

impl SECStatus
{
    pub fn to_result(&self) -> Result<(), String>
    {
        match *self
        {
            SECSuccess => Ok(()),
            SECFailure => Err(nspr::get_error_text()),
            SECWouldBlock => fail!("Unexpectedly got SECWouldBlock"),
        }
    }
}

#[repr(C)]
pub enum SECItemType
{
    siBuffer = 0,
    siClearDataBuffer = 1,
    siCipherDataBuffer = 2,
    siDERCertBuffer = 3,
    siEncodedCertBuffer = 4,
    siDERNameBuffer = 5,
    siEncodedNameBuffer = 6,
    siAsciiNameString = 7,
    siAsciiString = 8,
    siDEROID = 9,
    siUnsignedInteger = 10,
    siUTCTime = 11,
    siGeneralizedTime = 12,
    siVisibleString = 13,
    siUTF8String = 14,
    siBMPString = 15,
}

#[repr(C)]
pub struct SECItem
{
    typ: SECItemType,
    data: *const c_uchar,
    len: c_uint,
}

impl SECItem
{
    pub unsafe fn new(typ: SECItemType, buffer: &[u8]) -> SECItem
    {
        SECItem
        {
            typ: typ,
            data: buffer.as_ptr(),
            len: buffer.len() as c_uint,
        }
    }

    pub unsafe fn free(item: *mut SECItem)
    {
        SECITEM_FreeItem(item, true);
    }
}

#[link(name="nss3")]
extern "C"
{
    fn SECITEM_FreeItem(item: *mut SECItem, freeitem: bool);
}
