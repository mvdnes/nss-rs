use result::NSSResult;
use ffi::{pk11, sec};
use ffi::nspr::PRBool;
use std::{ptr, mem};
use libc::{c_uint, c_int, c_void};

#[allow(non_camel_case_types)]
#[derive(Copy)]
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
    fn to_secitem<'a>(&'a self) -> sec::SECItem<'a>
    {
        match *self
        {
            RSAPaddingParam::NullParam => sec::SECItem::empty(),
            RSAPaddingParam::OAEPParam(ref param) => sec::SECItem::from_struct(param),
        }
    }
}

impl RSAPadding
{
    fn to_ckm(&self) -> pk11::CK_MECHANISM_TYPE
    {
        match *self
        {
            RSAPadding::PKCS1v15 => pk11::CKM_RSA_PKCS,
            RSAPadding::OAEP_MGF1_SHA1
            | RSAPadding::OAEP_MGF1_SHA224
            | RSAPadding::OAEP_MGF1_SHA256
            | RSAPadding::OAEP_MGF1_SHA384
            | RSAPadding::OAEP_MGF1_SHA512 => pk11::CKM_RSA_PKCS_OAEP,
        }
    }

    fn get_param(&self) -> RSAPaddingParam
    {
        match *self
        {
            RSAPadding::PKCS1v15 => RSAPaddingParam::NullParam,
            RSAPadding::OAEP_MGF1_SHA1 => RSAPaddingParam::OAEPParam(pk11::CK_RSA_PKCS_OAEP_PARAMS::from_algorithm(pk11::CKM_SHA_1)),
            RSAPadding::OAEP_MGF1_SHA224 => RSAPaddingParam::OAEPParam(pk11::CK_RSA_PKCS_OAEP_PARAMS::from_algorithm(pk11::CKM_SHA_224)),
            RSAPadding::OAEP_MGF1_SHA256 => RSAPaddingParam::OAEPParam(pk11::CK_RSA_PKCS_OAEP_PARAMS::from_algorithm(pk11::CKM_SHA_256)),
            RSAPadding::OAEP_MGF1_SHA384 => RSAPaddingParam::OAEPParam(pk11::CK_RSA_PKCS_OAEP_PARAMS::from_algorithm(pk11::CKM_SHA_384)),
            RSAPadding::OAEP_MGF1_SHA512 => RSAPaddingParam::OAEPParam(pk11::CK_RSA_PKCS_OAEP_PARAMS::from_algorithm(pk11::CKM_SHA_512)),
        }
    }
}

pub struct RSAPrivateKey
{
    key: pk11::PrivateKey,
}

impl RSAPrivateKey
{
    pub fn load(data: &[u8]) -> NSSResult<RSAPrivateKey>
    {
        try!(::nss::init());

        let mut der = sec::SECItem::from_buf(data);
        let slot = try!(pk11::SlotInfo::get_internal());
        let mut key = ptr::null_mut();

        let pkey = unsafe
        {
            try!(pk11::PK11_ImportDERPrivateKeyInfoAndReturnKey(slot.get_mut(), der.get_mut(), ptr::null_mut(),
                                                                ptr::null_mut(), PRBool::False, PRBool::False, pk11::KU_ALL,
                                                                &mut key, ptr::null_mut()).to_result());
            try!(pk11::PrivateKey::wrap(key))
        };

        Ok(RSAPrivateKey { key: pkey })
    }

    pub fn gen(key_size_bits: u32) -> NSSResult<RSAPrivateKey>
    {
        try!(::nss::init());

        let slot = try!(pk11::SlotInfo::get_internal());
        let mut param = pk11::PK11RSAGenParams { key_size_bits: key_size_bits as c_int, pe: 65537, };
        let mut pubkey = ptr::null_mut();

        let privkey = unsafe
        {
            let param_ptr = mem::transmute::<_, *mut c_void>(&mut param);
            try!(pk11::PrivateKey::wrap(
                    pk11::PK11_GenerateKeyPair(slot.get_mut(), pk11::CKM_RSA_PKCS_KEY_PAIR_GEN, param_ptr,
                                               &mut pubkey, PRBool::False, PRBool::False, ptr::null_mut())
                    )
                )
        };

        let _ = pk11::PublicKey::wrap(pubkey); // This ensures the correct drop of pubkey
        Ok(RSAPrivateKey { key: privkey })
    }

    pub fn save(&mut self) -> NSSResult<Vec<u8>>
    {
        let secitem = unsafe
        {
            try!(sec::SECItem::wrap(pk11::PK11_ExportDERPrivateKeyInfo(self.key.get_mut(), ptr::null_mut())))
        };
        let result = secitem.copy_buf();
        Ok(result)
    }

    pub fn key_len(&mut self) -> usize
    {
        match self.get_public()
        {
            Err(..) => 0,
            Ok(public) => public.key_len(),
        }
    }

    pub fn encrypt(&mut self, padding: RSAPadding, data: &[u8]) -> NSSResult<Vec<u8>>
    {
        let mut public = try!(self.get_public());
        public.encrypt(padding, data)
    }

    pub fn decrypt(&mut self, padding: RSAPadding, data: &[u8]) -> NSSResult<Vec<u8>>
    {
        let mut out = Vec::with_capacity(self.key_len());
        let mut outlen = 0;

        let params = padding.get_param();
        let mut secitem = params.to_secitem();

        unsafe
        {
            try!(pk11::PK11_PrivDecrypt(self.key.get_mut(), padding.to_ckm(), secitem.get_mut(), out.as_mut_ptr(),
                                        &mut outlen, out.capacity() as c_uint, data.as_ptr(), data.len() as c_uint).to_result());
            out.set_len(outlen as usize);
        }

        Ok(out)
    }

    pub fn get_public(&mut self) -> NSSResult<RSAPublicKey>
    {
        let mypub = unsafe
        {
            try!(pk11::PublicKey::wrap(pk11::SECKEY_ConvertToPublicKey(self.key.get_mut())))
        };
        Ok(RSAPublicKey { key: mypub })
    }
}

pub struct RSAPublicKey
{
    key: pk11::PublicKey,
}

impl RSAPublicKey
{
    pub fn load(data: &[u8]) -> NSSResult<RSAPublicKey>
    {
        try!(::nss::init());

        let der = sec::SECItem::from_buf(data);

        let key = unsafe
        {
            let spki = try!(pk11::PublicKeyInfo::wrap(pk11::SECKEY_DecodeDERSubjectPublicKeyInfo(der.get())));
            try!(pk11::PublicKey::wrap(pk11::SECKEY_ExtractPublicKey(spki.get())))
        };

        Ok(RSAPublicKey { key: key })
    }

    pub fn save(&self) -> NSSResult<Vec<u8>>
    {
        let secitem = unsafe
        {
            try!(sec::SECItem::wrap(pk11::SECKEY_EncodeDERSubjectPublicKeyInfo(self.key.get())))
        };

        let result = secitem.copy_buf();
        Ok(result)
    }

    pub fn key_len(&self) -> usize
    {
        unsafe
        {
            pk11::SECKEY_PublicKeyStrength(self.key.get()) as usize
        }
    }

    pub fn encrypt(&mut self, padding: RSAPadding, data: &[u8]) -> NSSResult<Vec<u8>>
    {
        let mut out = Vec::with_capacity(self.key_len());
        let mut outlen = 0;

        let params = padding.get_param();
        let mut secitem = params.to_secitem();

        unsafe
        {

            try!(pk11::PK11_PubEncrypt(self.key.get_mut(), padding.to_ckm(), secitem.get_mut(), out.as_mut_ptr(),
                                       &mut outlen, out.capacity() as c_uint, data.as_ptr(), data.len() as c_uint,
                                       ptr::null_mut()).to_result());
            out.set_len(outlen as usize);
        }

        Ok(out)
    }
}

#[cfg(test)]
mod test
{
    extern crate rustc_serialize as serialize;
    use self::serialize::base64::FromBase64;

    static PUB_BASE64 : &'static [u8] = b"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL3F6TIc3JEYsugo+a2fPU3W+Epv/FeIX21DC86WYnpFtW4srFtz2oNUzyLUzDHZdb+k//8dcT3IAOzUUi3R2eMCAwEAAQ==";
    static PRIV_BASE64 : &'static [u8] = b"MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAvcXpMhzckRiy6Cj5rZ89Tdb4Sm/8V4hfbUMLzpZiekW1biysW3Pag1TPItTMMdl1v6T//x1xPcgA7NRSLdHZ4wIDAQABAkEAjh8+4qncwcmGivnM6ytbpQT+k/jEOeXG2bQhjojvnXN3FazGCEFXvpuIBcJVfaIJS9YBCMOzzrAtO0+k2hWnOQIhAOC4NVbo8FQhZS4yXM1M86kMl47FA9ui//OUfbhlAdw1AiEA2DBmIXnsboKB+OHver69p0gNeWlvcJc9bjDVfdLVsLcCIQCPtV3vGYJv2vdwxqZQaHC+YB4gIGAqOqBCbmjD3lyFLQIgA+VTYdUNoqwtZWvE4gRf7IzK2V5CCNhg3gR5RGwxN58CIGCcafoRrUKsM66ISg0ITI04G9V/w+wMx91wjEEB+QBz";

    #[test]
    fn decrypt()
    {
        static ENC_MESSAGE : &'static [u8] = b"C3fHQjn390troPLazlU5eW0A+p/wlJXv6nwPvEeDh3tCvJ8VWKdnpQbSYGEIuhiNZ8SqNepluES/izTHbXaSWA==";
        let encrypted = ENC_MESSAGE.from_base64().unwrap();

        let priv_der = PRIV_BASE64.from_base64().unwrap();
        let mut privkey = super::RSAPrivateKey::load(&priv_der).unwrap();

        let message = privkey.decrypt(super::RSAPadding::OAEP_MGF1_SHA1, &encrypted).unwrap();
        assert_eq!(b"Encrypt Me!", &*message);
    }

    #[test]
    fn priv_pub()
    {
        let priv_der = PRIV_BASE64.from_base64().unwrap();
        let pub_der = PUB_BASE64.from_base64().unwrap();

        let mut privkey = super::RSAPrivateKey::load(&priv_der).unwrap();
        let pubkey = privkey.get_public().unwrap();

        let derivedpub_der = pubkey.save().unwrap();
        assert_eq!(pub_der, derivedpub_der);
    }
}
