use result::{NSSError, UNKNOWN};
use libc::c_uint;

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

pub fn get_error_code() -> NSSError
{
    let code = unsafe { PR_GetError() };
    FromPrimitive::from_i32(code).unwrap_or(UNKNOWN)
}

#[link(name="nspr4")]
extern "C"
{
    pub fn PR_Init(_type: PRThreadType, priority: PRThreadPriority,
                   maxPTDs: c_uint);
    pub fn PR_Cleanup() -> PRStatus;
    fn PR_GetError() -> i32;
}
