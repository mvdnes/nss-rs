use result;
use libc::c_uint;
use std::c_str::CString;

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
    PR_True = 1,
    PR_False = 0,
}

pub fn get_error_code() -> result::NSSError
{
    let code = unsafe { PR_GetError() };
    result::NSS(code)
}

pub fn get_error_message(code: i32) -> Option<CString>
{
    if !error_code_exists(code) {
        return None;
    }

    static LANG_EN : u32 = 1;
    unsafe
    {
        let cmessage = PR_ErrorToString(code, LANG_EN);
        Some(CString::new(cmessage, false))
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
