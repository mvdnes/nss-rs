use result::NSSResult;
use ffi::{pk11, sec};
use std::{ptr, mem};
use libc::{c_uint, c_int, c_void};

#[allow(non_camel_case_types)]
pub enum RSAPadding
{
    PKCS1v15,
    OAEP_MGF1_SHA1,
    OAEP_MGF1_SHA224,
    OAEP_MGF1_SHA256,
    OAEP_MGF1_SHA384,
    OAEP_MGF1_SHA512,
}

enum RSAPaddingParam
{
    NullParam,
    OAEPParam(pk11::CK_RSA_PKCS_OAEP_PARAMS),
}

impl RSAPaddingParam
{
    unsafe fn to_secitem(&self) -> sec::SECItem
    {
        match *self
        {
            NullParam => sec::SECItem::from_struct(&()),
            OAEPParam(ref param) => sec::SECItem::from_struct(param),
        }
    }
}

impl RSAPadding
{
    fn to_ckm(&self) -> pk11::CK_MECHANISM_TYPE
    {
        match *self
        {
            PKCS1v15 => pk11::CKM_RSA_PKCS,
            OAEP_MGF1_SHA1
            | OAEP_MGF1_SHA224
            | OAEP_MGF1_SHA256
            | OAEP_MGF1_SHA384
            | OAEP_MGF1_SHA512 => pk11::CKM_RSA_PKCS_OAEP,
        }
    }

    fn get_param(&self) -> RSAPaddingParam
    {
        match *self
        {
            PKCS1v15 => NullParam,
            OAEP_MGF1_SHA1 => OAEPParam(pk11::CK_RSA_PKCS_OAEP_PARAMS::from_algorithm(pk11::CKM_SHA_1)),
            OAEP_MGF1_SHA224 => OAEPParam(pk11::CK_RSA_PKCS_OAEP_PARAMS::from_algorithm(pk11::CKM_SHA_224)),
            OAEP_MGF1_SHA256 => OAEPParam(pk11::CK_RSA_PKCS_OAEP_PARAMS::from_algorithm(pk11::CKM_SHA_256)),
            OAEP_MGF1_SHA384 => OAEPParam(pk11::CK_RSA_PKCS_OAEP_PARAMS::from_algorithm(pk11::CKM_SHA_384)),
            OAEP_MGF1_SHA512 => OAEPParam(pk11::CK_RSA_PKCS_OAEP_PARAMS::from_algorithm(pk11::CKM_SHA_512)),
        }
    }
}

pub struct RSAPrivateKey
{
    key: *mut pk11::SECKEYPrivateKey,
}

impl RSAPrivateKey
{
    pub fn load(data: &[u8]) -> NSSResult<RSAPrivateKey>
    {
        try!(::nss::init());
        unsafe
        {
            let mut der = sec::SECItem::new(data);
            let slot = try_ptr!(pk11::PK11_GetInternalKeySlot());
            let mut key = ptr::null_mut();

            try!(pk11::PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, &mut der, ptr::null_mut(), ptr::null_mut(), false, false, pk11::KU_ALL, &mut key, ptr::null_mut()).to_result());

            pk11::PK11_FreeSlot(slot);
            Ok(RSAPrivateKey { key: key })
        }
    }

    pub fn gen(key_size_bits: uint) -> NSSResult<RSAPrivateKey>
    {
        try!(::nss::init());
        unsafe
        {
            let slot = try_ptr!(pk11::PK11_GetInternalKeySlot());
            let mut param = pk11::PK11RSAGenParams { key_size_bits: key_size_bits as c_int, pe: 65537, };
            let param_ptr = mem::transmute::<_, *mut c_void>(&mut param);
            let mut pubkey = ptr::null_mut();
            let privkey = try_ptr!(pk11::PK11_GenerateKeyPair(slot, pk11::CKM_RSA_PKCS_KEY_PAIR_GEN, param_ptr, &mut pubkey, false, false, ptr::null_mut()));

            pk11::SECKEY_DestroyPublicKey(pubkey);
            pk11::PK11_FreeSlot(slot);

            Ok(RSAPrivateKey { key: privkey })
        }
    }

    pub fn save(&self) -> NSSResult<Vec<u8>>
    {
        unsafe
        {
            let secitem = try_ptr!(pk11::PK11_ExportDERPrivateKeyInfo(self.key, ptr::null_mut()));
            let result = (&*secitem).copy_buf();
            sec::SECItem::free(secitem);
            Ok(result)
        }
    }

    pub fn key_len(&self) -> uint
    {
        match self.get_public()
        {
            Err(..) => 0,
            Ok(public) => public.key_len(),
        }
    }

    pub fn encrypt(&self, padding: RSAPadding, data: &[u8]) -> NSSResult<Vec<u8>>
    {
        let public = try!(self.get_public());
        public.encrypt(padding, data)
    }

    pub fn decrypt(&self, padding: RSAPadding, data: &[u8]) -> NSSResult<Vec<u8>>
    {
        unsafe
        {
            let mut out = Vec::with_capacity(self.key_len());
            let mut outlen = 0;

            let params = padding.get_param();
            let mut secitem = params.to_secitem();

            try!(pk11::PK11_PrivDecrypt(self.key, padding.to_ckm(), &mut secitem, out.as_mut_ptr(),
                                        &mut outlen, out.capacity() as c_uint, data.as_ptr(), data.len() as c_uint).to_result());
            out.set_len(outlen as uint);
            Ok(out)
        }
    }

    pub fn get_public(&self) -> NSSResult<RSAPublicKey>
    {
        unsafe
        {
            let mypub = try_ptr!(pk11::SECKEY_ConvertToPublicKey(self.key));
            Ok(RSAPublicKey { key: mypub })
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
    pub fn load(data: &[u8]) -> NSSResult<RSAPublicKey>
    {
        try!(::nss::init());
        unsafe
        {
            let der = sec::SECItem::new(data);
            let spki = try_ptr!(pk11::SECKEY_DecodeDERSubjectPublicKeyInfo(&der));
            let key = try_ptr!(pk11::SECKEY_ExtractPublicKey(spki as *const pk11::CERTSubjectPublicKeyInfo));

            pk11::SECKEY_DestroySubjectPublicKeyInfo(spki);
            Ok(RSAPublicKey { key: key })
        }
    }

    pub fn save(&self) -> NSSResult<Vec<u8>>
    {
        unsafe
        {
            let secitem = try_ptr!(pk11::SECKEY_EncodeDERSubjectPublicKeyInfo(self.key as *const _));
            let result = (&*secitem).copy_buf();
            sec::SECItem::free(secitem);
            Ok(result)
        }
    }

    pub fn key_len(&self) -> uint
    {
        unsafe
        {
            pk11::SECKEY_PublicKeyStrength(self.key as *const pk11::SECKEYPublicKey) as uint
        }
    }

    pub fn encrypt(&self, padding: RSAPadding, data: &[u8]) -> NSSResult<Vec<u8>>
    {
        unsafe
        {
            let mut out = Vec::with_capacity(self.key_len());
            let mut outlen = 0;

            let params = padding.get_param();
            let mut secitem = params.to_secitem();

            try!(pk11::PK11_PubEncrypt(self.key, padding.to_ckm(), &mut secitem, out.as_mut_ptr(),
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
