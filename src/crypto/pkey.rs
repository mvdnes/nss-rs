use ffi::{pk11, sec};
use std::ptr;
use libc::c_uint;

pub enum Padding
{
//    OAEP, // TODO: http://dxr.mozilla.org/mozilla-central/source/security/nss/lib/util/pkcs11t.h#1257
    PKCS1v15,
}

impl Padding
{
    fn to_ffi_rsa(&self) -> pk11::CK_MECHANISM_TYPE
    {
        match *self
        {
            PKCS1v15 => pk11::CKM_RSA_PKCS,
//            OAEP => pk11::CKM_RSA_PKCS_OAEP,
        }
    }
}

pub struct RSAPrivateKey
{
    key: *mut pk11::SECKEYPrivateKey,
}

impl RSAPrivateKey
{
    pub fn load(data: &[u8]) -> Result<RSAPrivateKey, String>
    {
        unsafe
        {
            try!(::nss::init());
            let mut der = sec::SECItem::new(sec::siBuffer, data);
            let slot = try_ptr!(pk11::PK11_GetInternalKeySlot());
            let mut key = ptr::null_mut();
            try!(pk11::PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, &mut der, ptr::null_mut(), ptr::null_mut(), false, true, pk11::KU_ALL, &mut key, ptr::null_mut()).to_result());

            pk11::PK11_FreeSlot(slot);
            Ok(RSAPrivateKey { key: key })
        }
    }

    pub fn key_len(&self) -> uint
    {
        match RSAPublicKey::from_private(self)
        {
            Err(..) => 0,
            Ok(public) => public.key_len(),
        }
    }

    pub fn encrypt(&self, padding: Padding, data: &[u8]) -> Result<Vec<u8>, String>
    {
        let public = try!(RSAPublicKey::from_private(self));
        public.encrypt(padding, data)
    }

    pub fn decrypt(&self, padding: Padding, data: &[u8]) -> Result<Vec<u8>, String>
    {
        unsafe
        {
            let mut out = Vec::with_capacity(self.key_len());
            let mut outlen = 0;
            try!(pk11::PK11_PrivDecrypt(self.key, padding.to_ffi_rsa(), ptr::null_mut(), out.as_mut_ptr(),
                                        &mut outlen, out.capacity() as c_uint, data.as_ptr(), data.len() as c_uint).to_result());
            out.set_len(outlen as uint);
            Ok(out)
        }
    }
}

impl Drop for RSAPrivateKey
{
    fn drop(&mut self)
    {
        unsafe
        {
            pk11::SECKEY_DestroyPrivateKey(self.key);
        }
    }
}

pub struct RSAPublicKey
{
    key: *mut pk11::SECKEYPublicKey,
}

impl RSAPublicKey
{
    pub fn load(data: &[u8]) -> Result<RSAPublicKey, String>
    {
        unsafe
        {
            try!(::nss::init());
            let der = sec::SECItem::new(sec::siBuffer, data);
            let spki = try_ptr!(pk11::SECKEY_DecodeDERSubjectPublicKeyInfo(&der));
            let key = try_ptr!(pk11::SECKEY_ExtractPublicKey(spki as *const pk11::CERTSubjectPublicKeyInfo));

            pk11::SECKEY_DestroySubjectPublicKeyInfo(spki);
            Ok(RSAPublicKey { key: key })
        }
    }

    pub fn key_len(&self) -> uint
    {
        unsafe
        {
            pk11::SECKEY_PublicKeyStrength(self.key as *const pk11::SECKEYPublicKey) as uint
        }
    }

    pub fn from_private(input: &RSAPrivateKey) -> Result<RSAPublicKey, String>
    {
        unsafe
        {
            let mypub = try_ptr!(pk11::SECKEY_ConvertToPublicKey(input.key));
            Ok(RSAPublicKey { key: mypub })
        }
    }

    pub fn encrypt(&self, padding: Padding, data: &[u8]) -> Result<Vec<u8>, String>
    {
        unsafe
        {
            let mut out = Vec::with_capacity(self.key_len());
            let mut outlen = 0;
            try!(pk11::PK11_PubEncrypt(self.key, padding.to_ffi_rsa(), ptr::null_mut(), out.as_mut_ptr(),
                                       &mut outlen, out.capacity() as c_uint, data.as_ptr(), data.len() as c_uint,
                                       ptr::null_mut()).to_result());
            out.set_len(outlen as uint);
            Ok(out)
        }
    }
}

impl Drop for RSAPublicKey
{
    fn drop(&mut self)
    {
        unsafe
        {
            pk11::SECKEY_DestroyPublicKey(self.key);
        }
    }
}
