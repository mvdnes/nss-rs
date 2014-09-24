use ffi::sec;
use ffi::sec::{SECStatus, SECItem};
use libc::{c_void, c_int, c_uint};

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum CK_MECHANISM_TYPE
{
    CKM_RSA_PKCS      = 0x0000_0001,
    CKM_RSA_PKCS_OAEP = 0x0000_0009,
    CKM_DES_ECB     = 0x0000_0121,
    CKM_DES_CBC     = 0x0000_0122,
    CKM_DES_CBC_PAD = 0x0000_0125,
    CKM_AES_ECB     = 0x0000_1081,
    CKM_AES_CBC     = 0x0000_1082,
    CKM_AES_CBC_PAD = 0x0000_1085,
    // TODO: add the others
}

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum CK_ATTRIBUTE_TYPE
{
    CKA_ENCRYPT = 0x0000_0104,
    CKA_DECRYPT = 0x0000_0105,
    // TODO: add the others
}

#[repr(C)]
pub enum PK11Origin
{
    OriginNULL = 0,
    OriginDerive = 1,
    OriginGenerated = 2,
    OriginFortezzaHack = 3,
    OriginUnwrap = 4,
}

// Opaque structures, with pointer references only
#[repr(C)] pub struct PK11SlotInfo;
#[repr(C)] pub struct PK11Context;
#[repr(C)] pub struct PK11SymKey;
#[repr(C)] pub struct SECKEYPrivateKey;
#[repr(C)] pub struct SECKEYPublicKey;
#[repr(C)] pub struct CERTSubjectPublicKeyInfo;

pub static KU_ALL : c_uint = 0xFF;

#[link(name="nss3")]
extern "C"
{
    pub fn PK11_GetBestSlot(typ: CK_MECHANISM_TYPE, wincx: *mut c_void) -> *mut PK11SlotInfo;
    pub fn PK11_GetInternalKeySlot() -> *mut PK11SlotInfo;
    pub fn PK11_FreeSlot(slot: *mut PK11SlotInfo);
    pub fn PK11_ImportSymKey(slot: *mut PK11SlotInfo, cipher: CK_MECHANISM_TYPE, origin: PK11Origin,
                             operation: CK_ATTRIBUTE_TYPE, key: *mut sec::SECItem, wincx: *mut c_void)
        -> *mut PK11SymKey;
    pub fn PK11_FreeSymKey(key: *mut PK11SymKey);
    pub fn PK11_ParamFromIV(typ: CK_MECHANISM_TYPE, iv: *mut sec::SECItem) -> *mut sec::SECItem;
    pub fn PK11_CreateContextBySymKey(typ: CK_MECHANISM_TYPE, operation: CK_ATTRIBUTE_TYPE,
                                      symKey: *mut PK11SymKey, param: *mut sec::SECItem) -> *mut PK11Context;
    pub fn PK11_DestroyContext(context: *mut PK11Context, freeit: bool);
    pub fn PK11_CipherOp(context: *mut PK11Context, buf_out: *mut u8, outlen: *mut c_int,
                         maxout: c_int, buf_in: *const u8, inlen: c_int) -> SECStatus;
    pub fn PK11_DigestFinal(context: *mut PK11Context, data: *mut u8, outlen: *mut c_uint, length: c_uint) -> SECStatus;

    pub fn SECKEY_ConvertToPublicKey(private_key: *mut SECKEYPrivateKey) -> *mut SECKEYPublicKey;
    pub fn SECKEY_DestroyPrivateKey(private_key: *mut SECKEYPrivateKey);
    pub fn SECKEY_DestroyPublicKey(private_key: *mut SECKEYPublicKey);
    pub fn SECKEY_DecodeDERSubjectPublicKeyInfo(spkider: *const SECItem) -> *mut CERTSubjectPublicKeyInfo;
    pub fn SECKEY_DestroySubjectPublicKeyInfo(cert: *mut CERTSubjectPublicKeyInfo);
    pub fn SECKEY_ExtractPublicKey(cert_subject: *const CERTSubjectPublicKeyInfo) -> *mut SECKEYPublicKey;
    pub fn PK11_ImportDERPrivateKeyInfoAndReturnKey(slot: *mut PK11SlotInfo, derPKI: *mut SECItem, nickname: *mut SECItem,
                                                    publicValue: *mut SECItem, isPerm: bool, isPrivate: bool, usage: c_uint,
                                                    privk: *mut *mut SECKEYPrivateKey, wincx: *mut c_void) -> SECStatus;
    pub fn PK11_PubEncrypt(key: *mut SECKEYPublicKey, mechanism: CK_MECHANISM_TYPE, param: *mut SECItem, out: *mut u8,
                           out_len: *mut c_uint, max_len: c_uint, data: *const u8, data_len: c_uint, wincx: *mut c_void) -> SECStatus;
    pub fn SECKEY_PublicKeyStrength(key: *const SECKEYPublicKey) -> c_uint;
    pub fn PK11_PrivDecrypt(key: *mut SECKEYPrivateKey, mechanism: CK_MECHANISM_TYPE, param: *mut SECItem,
                            out: *mut u8, out_len: *mut c_uint, max_len: c_uint, enc: *const u8, enc_len: c_uint) -> SECStatus;
}
