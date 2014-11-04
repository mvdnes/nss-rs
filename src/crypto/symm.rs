use result::NSSResult;
use ffi::{pk11, sec};
use std::ptr;

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
            AES_ECB => pk11::CKM_AES_ECB,
            AES_CBC => pk11::CKM_AES_CBC,
            AES_CBC_PAD => pk11::CKM_AES_CBC_PAD,
            DES_ECB => pk11::CKM_DES_ECB,
            DES_CBC => pk11::CKM_DES_CBC,
            DES_CBC_PAD => pk11::CKM_DES_CBC_PAD,
        }
    }
}

pub struct Crypter
{
    kind: Kind,
    context: Option<pk11::Context>,
}

impl Crypter
{
    pub fn new(kind: Kind) -> NSSResult<Crypter>
    {
        try!(::nss::init());

        Ok(Crypter
           {
               kind: kind,
               context: None,
           })
    }

    fn mech(&self) -> pk11::CK_MECHANISM_TYPE
    {
        self.kind.to_ffi()
    }

    pub fn init(&mut self, mode: Mode, key: &[u8], iv: &[u8]) -> NSSResult<()>
    {
        let mut key_item = sec::SECItemBox::from_buf(key);
        let mut iv_item = sec::SECItemBox::from_buf(iv);

        let slot = try!(pk11::SlotInfo::get_best(self.mech()));

        let context = unsafe
        {
            let sym_key =
                try!(
                    pk11::SymKey::wrap(
                        pk11::PK11_ImportSymKey(slot.get_mut(), self.mech(),
                                                pk11::OriginUnwrap, mode.to_ffi(),
                                                key_item.get_mut(), ptr::null_mut())
                    )
                );
            let mut sec_param = try!(sec::SECItemBox::wrap(pk11::PK11_ParamFromIV(self.mech(), iv_item.get_mut())));
            try!(pk11::Context::wrap(pk11::PK11_CreateContextBySymKey(self.mech(), mode.to_ffi(), sym_key.get_mut(), sec_param.get_mut())))
        };

        self.context = Some(context);
        Ok(())
    }

    pub fn update(&mut self, in_buf: &[u8]) -> NSSResult<Vec<u8>>
    {
        let context = match self.context
        {
            None => return Err(::result::SEC_ERROR_NOT_INITIALIZED),
            Some(ref c) => c.get_mut(),
        };

        let mut out_buf = Vec::with_capacity(in_buf.len() + 128);
        let mut outlen = 0;

        unsafe
        {
            try!(pk11::PK11_CipherOp(context, out_buf.as_mut_ptr(), &mut outlen, out_buf.capacity() as ::libc::c_int,
                                     in_buf.as_ptr(), in_buf.len() as ::libc::c_int)
                 .to_result()
            );
            out_buf.set_len(outlen as uint);
        }

        Ok(out_buf)
    }

    pub fn finalize(&mut self) -> NSSResult<Vec<u8>>
    {
        let context = match self.context
        {
            None => return Err(::result::SEC_ERROR_NOT_INITIALIZED),
            Some(ref c) => c.get_mut(),
        };

        let mut out_buf = Vec::with_capacity(2048);
        let mut outlen = 0;

        unsafe
        {
            try!(pk11::PK11_DigestFinal(context, out_buf.as_mut_ptr(), &mut outlen,
                                        out_buf.capacity() as ::libc::c_uint)
                 .to_result()
            );
            out_buf.set_len(outlen as uint);
        }

        Ok(out_buf)
    }
}

#[cfg(test)]
mod test
{
    use super::Crypter;

    fn test_fips(kind: super::Kind, key: &[u8], plain: &[u8], result: &[u8])
    {
        let mut c = Crypter::new(kind).unwrap();

        c.init(super::Encrypt, key, b"").unwrap();

        let p1 = c.update(plain).unwrap();
        let p2 = c.finalize().unwrap();
        assert_eq!((p1 + p2).as_slice(), result);

        c.init(super::Decrypt, key, b"").unwrap();

        let r1 = c.update(result).unwrap();
        let r2 = c.finalize().unwrap();
        assert_eq!((r1 + r2).as_slice(), plain);
    }

    #[test]
    fn fips_197_128()
    {
        let key : &[u8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let plain : &[u8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let result: &[u8] = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a];

        test_fips(super::AES_ECB, key, plain, result);
    }

    #[test]
    fn fips_197_192()
    {
        let key : &[u8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                           0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let plain : &[u8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let result: &[u8] = [0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91];

        test_fips(super::AES_ECB, key, plain, result);
    }

    #[test]
    fn fips_197_256()
    {
        let key : &[u8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
        let plain : &[u8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let result: &[u8] = [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89];

        test_fips(super::AES_ECB, key, plain, result);
    }
}
