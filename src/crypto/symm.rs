use result::NSSResult;
use ffi::{pk11, sec};
use std::ptr;

#[derive(Copy)]
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
            Mode::Encrypt => pk11::CKA_ENCRYPT,
            Mode::Decrypt => pk11::CKA_DECRYPT,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy)]
pub enum Kind
{
    AES_ECB,
    AES_CBC,
    AES_CBC_PAD,
    DES_ECB,
    DES_CBC,
    DES_CBC_PAD,
}

impl Kind 
{
    fn to_ffi(&self) -> pk11::CK_MECHANISM_TYPE
    {
        match *self
        {
            Kind::AES_ECB => pk11::CKM_AES_ECB,
            Kind::AES_CBC => pk11::CKM_AES_CBC,
            Kind::AES_CBC_PAD => pk11::CKM_AES_CBC_PAD,
            Kind::DES_ECB => pk11::CKM_DES_ECB,
            Kind::DES_CBC => pk11::CKM_DES_CBC,
            Kind::DES_CBC_PAD => pk11::CKM_DES_CBC_PAD,
        }
    }
}

pub struct Crypter
{
    context: pk11::Context,
}

impl Crypter
{
    pub fn new(kind: Kind, mode: Mode, key: &[u8], iv: &[u8]) -> NSSResult<Crypter>
    {
        try!(::nss::init());

        let mech = kind.to_ffi();
        let mut key_item = sec::SECItem::from_buf(key);
        let mut iv_item = sec::SECItem::from_buf(iv);

        let slot = try!(pk11::SlotInfo::get_best(mech));

        let context = unsafe
        {
            let mut sym_key =
                try!(
                    pk11::SymKey::wrap(
                        pk11::PK11_ImportSymKey(slot.get_mut(), mech,
                                                pk11::PK11Origin::OriginUnwrap, mode.to_ffi(),
                                                key_item.get_mut(), ptr::null_mut())
                    )
                );
            let mut sec_param = try!(sec::SECItem::wrap(pk11::PK11_ParamFromIV(mech, iv_item.get_mut())));
            try!(pk11::Context::wrap(pk11::PK11_CreateContextBySymKey(mech, mode.to_ffi(), sym_key.get_mut(), sec_param.get_mut())))
        };

        Ok(Crypter {
            context: context
        })
    }

    pub fn update(&mut self, in_buf: &[u8]) -> NSSResult<Vec<u8>>
    {
        let mut out_buf = Vec::with_capacity(in_buf.len() + 128);
        let mut outlen = 0;

        unsafe
        {
            try!(pk11::PK11_CipherOp(self.context.get_mut(), out_buf.as_mut_ptr(), &mut outlen, out_buf.capacity() as ::libc::c_int,
                                     in_buf.as_ptr(), in_buf.len() as ::libc::c_int)
                 .to_result()
            );
            out_buf.set_len(outlen as usize);
        }

        Ok(out_buf)
    }

    pub fn finalize(&mut self, in_buf: &[u8]) -> NSSResult<Vec<u8>>
    {
        let mut result = Vec::new();
        if in_buf.len() != 0 {
            result = try!(self.update(in_buf));
        }

        let mut out_buf = Vec::with_capacity(2048);
        let mut outlen = 0;

        unsafe
        {
            try!(pk11::PK11_DigestFinal(self.context.get_mut(), out_buf.as_mut_ptr(), &mut outlen,
                                        out_buf.capacity() as ::libc::c_uint)
                 .to_result()
            );
            out_buf.set_len(outlen as usize);
        }

        result = result + &*out_buf;
        Ok(result)
    }
}

#[cfg(test)]
mod test
{
    use super::Crypter;

    fn test_fips(key: &[u8], plain: &[u8], result: &[u8])
    {
        let mut c = Crypter::new(super::Kind::AES_ECB, super::Mode::Encrypt, key, b"").unwrap();

        let p = c.finalize(plain).unwrap();
        assert_eq!(p, result);

        let mut c = Crypter::new(super::Kind::AES_ECB, super::Mode::Decrypt, key, b"").unwrap();

        let r = c.finalize(result).unwrap();
        assert_eq!(r, plain);
    }

    #[test]
    fn fips_197_128()
    {
        let key : &[u8] =   &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let plain : &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let result: &[u8] = &[0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a];

        test_fips(key, plain, result);
    }

    #[test]
    fn fips_197_192()
    {
        let key : &[u8] =   &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                              0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let plain : &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let result: &[u8] = &[0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91];

        test_fips(key, plain, result);
    }

    #[test]
    fn fips_197_256()
    {
        let key : &[u8] =   &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
        let plain : &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let result: &[u8] = &[0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89];

        test_fips(key, plain, result);
    }
}
