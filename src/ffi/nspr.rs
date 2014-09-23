//#[allow(non_camel_case_types)]

use libc::c_uint;

#[repr(C)]
pub enum PRThreadPriority
{
    PR_PRIORITY_LOW = 0,
    PR_PRIORITY_NORMAL,
    PR_PRIORITY_HIGH,
    PR_PRIORITY_URGENT,
}

#[repr(C)]
pub enum PRThreadType
{
    PR_USER_THREAD = 0,
    PR_SYSTEM_THREAD,
}

#[repr(C)]
pub enum PRStatus
{
    PR_FAILURE = -1,
    PR_SUCCESS = 0,
}

#[link(name="nspr4")]
extern "C"
{
    pub fn PR_Init(_type: PRThreadType, priority: PRThreadPriority,
                   maxPTDs: c_uint);
    pub fn PR_Cleanup() -> PRStatus;
}
