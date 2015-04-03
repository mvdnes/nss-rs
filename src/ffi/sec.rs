use result::NSSResult;
use ffi::nspr;
use ffi::nspr::PRBool;
use libc::{c_uint, c_uchar};
use std::{mem, ptr};
use std::marker::PhantomData;

#[must_use]
#[repr(C)]
#[allow(dead_code)] // List all available options
pub enum SECStatus
{
    WouldBlock = -2,
    Failure = -1,
    Success = 0
}

impl SECStatus
{
    pub fn to_result(&self) -> ::result::NSSResult<()>
    {
        match *self
        {
            SECStatus::Success => Ok(()),
            SECStatus::Failure => Err(nspr::get_error_code()),
            SECStatus::WouldBlock => panic!("Unexpectedly got SECWouldBlock"),
        }
    }
}

#[repr(C)]
#[allow(dead_code)] // We just list all available in NSS
enum SECItemType
{
    Buffer = 0,
    ClearDataBuffer = 1,
    CipherDataBuffer = 2,
    DERCertBuffer = 3,
    EncodedCertBuffer = 4,
    DERNameBuffer = 5,
    EncodedNameBuffer = 6,
    AsciiNameString = 7,
    AsciiString = 8,
    DEROID = 9,
    UnsignedInteger = 10,
    UTCTime = 11,
    GeneralizedTime = 12,
    VisibleString = 13,
    UTF8String = 14,
    BMPString = 15,
}

#[repr(C)]
pub struct SECItemFFI
{
    typ: SECItemType,
    data: *const c_uchar,
    len: c_uint,
}

pub enum SECItem<'a>
{
    Boxed(*mut SECItemFFI),
    // This struct contains PhantomData, to ensure SECItemFFi does not live too long
    Data(SECItemFFI, PhantomData<&'a ()>)
}

impl SECItem<'static>
{
    pub fn wrap(data: *mut SECItemFFI) -> NSSResult<SECItem<'static>>
    {
        match data.is_null()
        {
            true => Err(nspr::get_error_code()),
            false => Ok(SECItem::Boxed(data)),
        }
    }

    pub fn empty() -> SECItem<'static>
    {
        SECItem::Data(SECItemFFI {
            typ: SECItemType::Buffer,
            data: ptr::null(),
            len: 0,
        }, PhantomData)
    }
}

impl<'a> SECItem<'a>
{
    pub fn from_buf(buffer: &'a [u8]) -> SECItem<'a>
    {
        let si = SECItemFFI
        {
            typ: SECItemType::Buffer,
            data: buffer.as_ptr(),
            len: buffer.len() as c_uint,
        };
        SECItem::Data(si, PhantomData)
    }

    pub fn from_struct<T>(data: &'a T) -> SECItem<'a>
    {
        let len = mem::size_of::<T>() as c_uint;
        let ptr = match len
        {
            0 => ptr::null(),
            _ => unsafe { mem::transmute(data) },
        };
        let si = SECItemFFI
        {
            typ: SECItemType::Buffer,
            data: ptr,
            len: len,
        };
        SECItem::Data(si, PhantomData)
    }

    pub fn get<'b>(&'b self) -> &'b SECItemFFI
    {
        match *self
        {
            SECItem::Boxed(ptr) => unsafe { &*ptr }, // Constructor should ensure ptr is not null
            SECItem::Data(ref si, _) => si,
        }
    }

    pub fn get_mut<'b>(&'b mut self) -> &'b mut SECItemFFI
    {
        match *self
        {
            SECItem::Boxed(ptr) => unsafe { &mut *ptr }, // Constructor should ensure ptr is not null
            SECItem::Data(ref mut si, _) => si,
        }
    }

    pub fn copy_buf(&self) -> Vec<u8>
    {
        let si = self.get();
        let buf : &[u8] = unsafe { ::std::slice::from_raw_parts(si.data, si.len as usize) };
        buf.to_vec()
    }
}

impl<'a> Drop for SECItem<'a>
{
    fn drop(&mut self)
    {
        match *self
        {
            SECItem::Boxed(ptr) => unsafe { SECITEM_FreeItem(ptr, PRBool::True) },
            _ => {},
        }
    }
}

#[link(name="nss3")]
extern "C"
{
    fn SECITEM_FreeItem(item: *mut SECItemFFI, freeitem: PRBool);
}
