use ffi::{pk11, sec};
use std::{ptr, mem};

pub enum Mode
{
    Encrypt,
    Decrypt,
}

impl Mode
{
    fn to_ffi(&self) -> pk11::CK_ATTRIBUTE_TYPE
    {
        match *self
        {
            Encrypt => pk11::CKA_ENCRYPT,
            Decrypt => pk11::CKA_DECRYPT,
        }
    }
}

#[allow(non_camel_case_types)]
pub enum Type
{
    AES_128_ECB,
    AES_128_CBC,
}

impl Type
{
    fn to_ffi(&self, pad: bool) -> Option<pk11::CK_MECHANISM_TYPE>
    {
        match (*self, pad)
        {
            (AES_128_ECB, false) => Some(pk11::CKM_AES_ECB),
            (AES_128_CBC, false) => Some(pk11::CKM_AES_CBC),
            (AES_128_CBC, true) => Some(pk11::CKM_AES_CBC_PAD),
            _ => None,
        }
    }

    pub fn key_len(&self) -> uint
    {
        match *self
        {
            AES_128_ECB
            | AES_128_CBC => 16
        }
    }
}

pub struct Crypter
{
    pad: bool,
    typ: Type,
    context: Option<*mut pk11::PK11Context>,
}

impl Crypter
{
    pub fn new(t: Type, pad: bool) -> Result<Crypter, String>
    {
        match t.to_ffi(pad)
        {
            Some(..) => {},
            None => return Err("Unsupported type/padding combination".to_string()),
        };
        Ok(Crypter
           {
               pad: pad,
               typ: t,
               context: None,
           })
    }

    fn mech(&self) -> pk11::CK_MECHANISM_TYPE
    {
        self.typ.to_ffi(self.pad).unwrap()
    }

    fn free_context(&mut self)
    {
        let context = mem::replace(&mut self.context, None);
        match context
        {
            None => {},
            Some(c) => unsafe { pk11::PK11_DestroyContext(c, true); },
        }
    }

    pub fn init(&mut self, mode: Mode, key: &[u8], iv: &[u8]) -> Result<(), String>
    {
        self.free_context();

        let needed_key_len = self.typ.key_len();
        if key.len() != needed_key_len
        {
            return Err(format!("Invalid key length. Should be {} bytes.", needed_key_len));
        }

        unsafe
        {
            let mut key_item = sec::SECItem::new(sec::siBuffer, key);
            let mut iv_item = sec::SECItem::new(sec::siBuffer, iv);

            let slot = try_ptr!(pk11::PK11_GetBestSlot(self.mech(), ptr::null_mut()));
            let sym_key = try_ptr!(pk11::PK11_ImportSymKey(slot, self.mech(), pk11::OriginUnwrap, mode.to_ffi(), &mut key_item, ptr::null_mut()));
            let sec_param = try_ptr!(pk11::PK11_ParamFromIV(self.mech(), &mut iv_item));
            let context = try_ptr!(pk11::PK11_CreateContextBySymKey(self.mech(), mode.to_ffi(), sym_key, sec_param));

            self.context = Some(context);

            sec::SECItem::free(sec_param);
            pk11::PK11_FreeSymKey(sym_key);
            pk11::PK11_FreeSlot(slot);

            Ok(())
        }
    }

    pub fn update(&mut self, in_buf: &[u8]) -> Result<Vec<u8>, String>
    {
        let context = match self.context
        {
            None => return Err("Not initialized".to_string()),
            Some(c) => c,
        };
        let mut out_buf = Vec::with_capacity(in_buf.len() + 128);
        unsafe
        {
            let mut outlen = 0;
            let status = pk11::PK11_CipherOp(context, out_buf.as_mut_ptr(), &mut outlen, out_buf.capacity() as ::libc::c_int, in_buf.as_ptr(), in_buf.len() as ::libc::c_int);
            try!(status.to_result());
            out_buf.set_len(outlen as uint);
        }
        Ok(out_buf)
    }

    pub fn final(&mut self) -> Result<Vec<u8>, String>
    {
        let context = match self.context
        {
            None => return Err("Not initialized".to_string()),
            Some(c) => c,
        };
        let mut out_buf = Vec::with_capacity(2048);
        unsafe
        {
            let mut outlen = 0;
            let status = pk11::PK11_DigestFinal(context, out_buf.as_mut_ptr(), &mut outlen, out_buf.capacity() as ::libc::c_uint);
            try!(status.to_result());
            out_buf.set_len(outlen as uint);
        }
        Ok(out_buf)
    }
}

impl Drop for Crypter
{
    fn drop(&mut self)
    {
        self.free_context();
    }
}
