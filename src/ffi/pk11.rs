use ffi::sec;
use ffi::sec::{SECStatus, SECItem};
use libc::{c_void, c_int, c_uint, c_ulong};
use std::ptr;

#[allow(non_camel_case_types)]
pub type CK_MECHANISM_TYPE = c_ulong;

pub const CKM_RSA_PKCS_KEY_PAIR_GEN : CK_MECHANISM_TYPE = 0x0000_0000;
pub const CKM_RSA_PKCS      : CK_MECHANISM_TYPE = 0x0000_0001;
pub const CKM_RSA_PKCS_OAEP : CK_MECHANISM_TYPE = 0x0000_0009;

pub const CKM_SHA_1   : CK_MECHANISM_TYPE = 0x0000_0220;
pub const CKM_SHA_224 : CK_MECHANISM_TYPE = 0x0000_0255;
pub const CKM_SHA_256 : CK_MECHANISM_TYPE = 0x0000_0250;
pub const CKM_SHA_384 : CK_MECHANISM_TYPE = 0x0000_0260;
pub const CKM_SHA_512 : CK_MECHANISM_TYPE = 0x0000_0270;

pub const CKM_DES_ECB     : CK_MECHANISM_TYPE = 0x0000_0121;
pub const CKM_DES_CBC     : CK_MECHANISM_TYPE = 0x0000_0122;
pub const CKM_DES_CBC_PAD : CK_MECHANISM_TYPE = 0x0000_0125;
pub const CKM_AES_ECB     : CK_MECHANISM_TYPE = 0x0000_1081;
pub const CKM_AES_CBC     : CK_MECHANISM_TYPE = 0x0000_1082;
pub const CKM_AES_CBC_PAD : CK_MECHANISM_TYPE = 0x0000_1085;
// CK_MECHANISM_TYPE

#[allow(non_camel_case_types)]
pub type CK_ATTRIBUTE_TYPE = c_ulong;

pub const CKA_ENCRYPT : CK_ATTRIBUTE_TYPE = 0x0000_0104;
pub const CKA_DECRYPT : CK_ATTRIBUTE_TYPE = 0x0000_0105;
// CK_ATTRIBUTE_TYPE

#[allow(non_camel_case_types)]
type CK_RSA_PKCS_MGF_TYPE = c_ulong;

const CKG_MGF1_SHA1   : CK_RSA_PKCS_MGF_TYPE = 0x0000_0001;
const CKG_MGF1_SHA224 : CK_RSA_PKCS_MGF_TYPE = 0x0000_0005;
const CKG_MGF1_SHA256 : CK_RSA_PKCS_MGF_TYPE = 0x0000_0002;
const CKG_MGF1_SHA384 : CK_RSA_PKCS_MGF_TYPE = 0x0000_0003;
const CKG_MGF1_SHA512 : CK_RSA_PKCS_MGF_TYPE = 0x0000_0004;
// CK_RSA_PKCS_MGF_TYPE

#[repr(C)]
#[allow(dead_code)] // List all available options
pub enum PK11Origin
{
    OriginNULL = 0,
    OriginDerive = 1,
    OriginGenerated = 2,
    OriginFortezzaHack = 3,
    OriginUnwrap = 4,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct CK_RSA_PKCS_OAEP_PARAMS
{
    hash_alg: CK_MECHANISM_TYPE,
    mgf: CK_RSA_PKCS_MGF_TYPE,
    source: c_ulong,
    data_source: *mut c_void,
    data_len: c_ulong,
}

impl CK_RSA_PKCS_OAEP_PARAMS
{
    pub fn from_algorithm(ckm: CK_MECHANISM_TYPE) -> CK_RSA_PKCS_OAEP_PARAMS
    {
        let mgf = mgf_type_from_ckm(ckm);
        CK_RSA_PKCS_OAEP_PARAMS
        {
            hash_alg: ckm,
            mgf: mgf,
            source: CKZ_DATA_SPECIFIED,
            data_source: ptr::null_mut(),
            data_len: 0,
        }
    }
}

fn mgf_type_from_ckm(ckm: CK_MECHANISM_TYPE) -> CK_RSA_PKCS_MGF_TYPE
{
    match ckm
    {
        CKM_SHA_1 => CKG_MGF1_SHA1,
        CKM_SHA_224 => CKG_MGF1_SHA224,
        CKM_SHA_256 => CKG_MGF1_SHA256,
        CKM_SHA_384 => CKG_MGF1_SHA384,
        CKM_SHA_512 => CKG_MGF1_SHA512,
        _ => fail!("Unsupported mechanism provided"),
    }
}

pub struct PK11RSAGenParams
{
    pub key_size_bits: c_int,
    pub pe: c_ulong,
}

// Opaque structures, with pointer references only
#[repr(C)] pub struct PK11SlotInfo;
#[repr(C)] pub struct PK11Context;
#[repr(C)] pub struct PK11SymKey;
#[repr(C)] pub struct SECKEYPrivateKey;
#[repr(C)] pub struct SECKEYPublicKey;
#[repr(C)] pub struct CERTSubjectPublicKeyInfo;

pub const KU_ALL : c_uint = 0xFF;
pub const CKZ_DATA_SPECIFIED : c_ulong = 0x0000_0001;

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
    pub fn PK11_GenerateKeyPair(slot: *mut PK11SlotInfo, kind: CK_MECHANISM_TYPE, param: *mut c_void, pub_key: *mut *mut SECKEYPublicKey,
                                token: bool, sensitive: bool, wincx: *mut c_void) -> *mut SECKEYPrivateKey;
    pub fn SECKEY_EncodeDERSubjectPublicKeyInfo(pubk: *const SECKEYPublicKey) -> *mut SECItem;
    pub fn PK11_ExportDERPrivateKeyInfo(privk: *mut SECKEYPrivateKey, wincx: *mut c_void) -> *mut SECItem;
}
