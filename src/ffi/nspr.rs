use result::NSSError;
use libc::c_uint;
use std::ffi::c_str_to_bytes;

#[repr(C)]
#[allow(dead_code)] // List all available options
pub enum PRThreadPriority
{
    PR_PRIORITY_LOW = 0,
    PR_PRIORITY_NORMAL = 1,
    PR_PRIORITY_HIGH = 2,
    PR_PRIORITY_URGENT = 3,
}

#[repr(C)]
#[allow(dead_code)] // List all available options
pub enum PRThreadType
{
    PR_USER_THREAD,
    PR_SYSTEM_THREAD,
}

#[repr(C)]
#[allow(dead_code)] // List all available options
pub enum PRStatus
{
    PR_FAILURE = -1,
    PR_SUCCESS = 0,
}

#[repr(C)]
pub enum PRBool
{
    True = 1,
    False = 0,
}

pub fn get_error_code() -> NSSError
{
    let code = unsafe { PR_GetError() };
    NSSError::NSS(code)
}

pub fn get_error_message(code: i32) -> Option<String>
{
    if !error_code_exists(code) {
        return None;
    }

    static LANG_EN : u32 = 1;
    unsafe
    {
        let cmessage = PR_ErrorToString(code, LANG_EN);
        let rmessage = String::from_utf8_lossy(c_str_to_bytes(&cmessage));
        Some(rmessage.into_owned())
    }
}

fn error_code_exists(code: i32) -> bool
{
    if code >= 0 && code < 256 {
        return true;
    }

    unsafe { !PR_ErrorToName(code).is_null() }
}

#[link(name="nspr4")]
extern "C"
{
    pub fn PR_Init(_type: PRThreadType, priority: PRThreadPriority,
                   maxPTDs: c_uint);
    pub fn PR_Cleanup() -> PRStatus;
    fn PR_GetError() -> i32;
    fn PR_ErrorToString(code: i32, language: u32) -> *const ::libc::c_char;
    fn PR_ErrorToName(code: i32) -> *const ::libc::c_char;
}
