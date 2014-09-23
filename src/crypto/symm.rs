use ffi::{pk11, sec};
use std::ptr;

pub enum Mode
{
    Encrypt,
    Decrypt,
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
}

pub struct Crypter
{
    mechanism: pk11::CK_MECHANISM_TYPE,
    key: Vec<u8>,
    iv: Vec<u8>,
    context: Option<*mut pk11::PK11Context>,
}

impl Crypter
{
    pub fn new(t: Type, pad: bool) -> Result<Crypter, String>
    {
        let mechanism = match t.to_ffi(pad)
        {
            Some(m) => m,
            None => return Err("Unsupported type/padding combination".to_string()),
        };
        Ok(Crypter
           {
               mechanism: mechanism,
               context: None,
               key: Vec::new(),
               iv: Vec::new(),
           })
    }

    pub fn init(&mut self, mode: Mode, key: Vec<u8>, iv: Vec<u8>)
    {
        self.key = key;
        self.iv = iv;
        let mut key_item = unsafe { sec::SECItem::new(sec::siBuffer, self.key.as_slice()) };
        let mut iv_item = unsafe { sec::SECItem::new(sec::siBuffer, self.iv.as_slice()) };
        let slot = unsafe
        {
            let s = pk11::PK11_GetBestSlot(self.mechanism, ptr::null_mut());
            if s.is_null() { return; }
            s
        };
        let symkey = unsafe
        {
            let s = pk11::PK11_ImportSymKey(slot, self.mechanism, pk11::OriginUnwrap, pk11::CKA_ENCRYPT, &mut key_item, ptr::null_mut());
            if s.is_null() { return; }
            s
        };

        let sec_param = unsafe { pk11::PK11_ParamFromIV(self.mechanism, &mut iv_item) };

        self.context = Some(
            unsafe { pk11::PK11_CreateContextBySymKey(self.mechanism, pk11::CKA_ENCRYPT, symkey, sec_param) }
            );

        unsafe { sec::SECItem::free(sec_param); }
    }
}
