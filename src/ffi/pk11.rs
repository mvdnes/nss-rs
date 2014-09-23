use super::sec;
use libc::c_void;

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum CK_MECHANISM_TYPE
{
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

#[repr(C)]
pub struct PK11SlotInfo;
#[repr(C)]
pub struct PK11Context;
#[repr(C)]
pub struct PK11SymKey;

#[link(name="nss3")]
extern "C"
{
    pub fn PK11_GetBestSlot(typ: CK_MECHANISM_TYPE, wincx: *mut c_void) -> *mut PK11SlotInfo;
    pub fn PK11_ImportSymKey(slot: *mut PK11SlotInfo, cipher: CK_MECHANISM_TYPE, origin: PK11Origin,
                             operation: CK_ATTRIBUTE_TYPE, key: *mut sec::SECItem, wincx: *mut c_void)
        -> *mut PK11SymKey;
    pub fn PK11_ParamFromIV(typ: CK_MECHANISM_TYPE, iv: *mut sec::SECItem) -> *mut sec::SECItem;
    pub fn PK11_CreateContextBySymKey(typ: CK_MECHANISM_TYPE, operation: CK_ATTRIBUTE_TYPE,
                                      symKey: *mut PK11SymKey, param: *mut sec::SECItem) -> *mut PK11Context;
    pub fn PK11_DestroyContext(context: *mut PK11Context, freeit: bool);
}
