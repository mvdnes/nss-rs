use result::NSSResult;
use ffi::nspr;
use ffi::nspr::{PRBool, PR_True};
use libc::{c_uint, c_uchar};
use std::{mem, ptr};
use std::kinds::marker::ContravariantLifetime;

#[must_use]
#[repr(C)]
#[allow(dead_code)] // List all available options
pub enum SECStatus
{
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0
}

impl SECStatus
{
    pub fn to_result(&self) -> ::result::NSSResult<()>
    {
        match *self
        {
            SECSuccess => Ok(()),
            SECFailure => Err(nspr::get_error_code()),
            SECWouldBlock => panic!("Unexpectedly got SECWouldBlock"),
        }
    }
}

#[repr(C)]
#[allow(dead_code)] // We just list all available in NSS
enum SECItemType
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

pub enum SECItemBox<'a>
{
    SIBox(*mut SECItem),
    SIData(SECItem, ContravariantLifetime<'a>)
}

impl SECItemBox<'static>
{
    pub fn wrap(data: *mut SECItem) -> NSSResult<SECItemBox<'static>>
    {
        match data.is_null()
        {
            true => Err(nspr::get_error_code()),
            false => Ok(SIBox(data)),
        }
    }

    pub fn empty() -> SECItemBox<'static>
    {
        SIData(SECItem {
            typ: siBuffer,
            data: ptr::null(),
            len: 0,
        }, ContravariantLifetime)
    }
}

impl<'a> SECItemBox<'a>
{
    pub fn from_buf(buffer: &'a [u8]) -> SECItemBox<'a>
    {
        let si = SECItem
        {
            typ: siBuffer,
            data: buffer.as_ptr(),
            len: buffer.len() as c_uint,
        };
        SIData(si, ContravariantLifetime)
    }

    pub fn from_struct<T>(data: &'a T) -> SECItemBox<'a>
    {
        let len = mem::size_of::<T>() as c_uint;
        let ptr = match len
        {
            0 => ptr::null(),
            _ => unsafe { mem::transmute(data) },
        };
        let si = SECItem
        {
            typ: siBuffer,
            data: ptr,
            len: len,
        };
        SIData(si, ContravariantLifetime)
    }

    pub fn get<'b>(&'b self) -> &'b SECItem
    {
        match *self
        {
            SIBox(ptr) => unsafe { ptr.as_ref().unwrap() },
            SIData(ref si, _) => si,
        }
    }

    pub fn get_mut<'b>(&'b mut self) -> &'b mut SECItem
    {
        match *self
        {
            SIBox(ptr) => unsafe { ptr.as_mut().unwrap() },
            SIData(ref mut si, _) => si,
        }
    }

    pub fn copy_buf(&self) -> Vec<u8>
    {
        let si = self.get();
        let buf : &[u8] = unsafe { mem::transmute(::std::raw::Slice { data: si.data, len: si.len as uint, }) };
        buf.to_vec()
    }
}

#[unsafe_destructor]
impl<'a> Drop for SECItemBox<'a>
{
    fn drop(&mut self)
    {
        match *self
        {
            SIBox(ptr) => unsafe { SECITEM_FreeItem(ptr, PR_True) },
            _ => {},
        }
    }
}

#[link(name="nss3")]
extern "C"
{
    fn SECITEM_FreeItem(item: *mut SECItem, freeitem: PRBool);
}
