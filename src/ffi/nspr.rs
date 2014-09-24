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

#[repr(i32)]
#[deriving(Show, FromPrimitive)]
#[allow(non_camel_case_types)]
pub enum PRError
{
    /// Unkown / No error
    UNKNOWN = 0,

    /// Memory allocation attempt failed
    PR_OUT_OF_MEMORY_ERROR = -6000,

    /// Invalid file descriptor
    PR_BAD_DESCRIPTOR_ERROR = -5999,

    /// The operation would have blocked
    PR_WOULD_BLOCK_ERROR = -5998,

    /// Invalid memory address argument
    PR_ACCESS_FAULT_ERROR = -5997,

    /// Invalid function for file type
    PR_INVALID_METHOD_ERROR = -5996,

    /// Invalid memory address argument
    PR_ILLEGAL_ACCESS_ERROR = -5995,

    /// Some unknown error has occurred
    PR_UNKNOWN_ERROR = -5994,

    /// Operation interrupted by another thread
    PR_PENDING_INTERRUPT_ERROR = -5993,

    /// function not implemented
    PR_NOT_IMPLEMENTED_ERROR = -5992,

    /// I/O function error
    PR_IO_ERROR = -5991,

    /// I/O operation timed out
    PR_IO_TIMEOUT_ERROR = -5990,

    /// I/O operation on busy file descriptor
    PR_IO_PENDING_ERROR = -5989,

    /// The directory could not be opened
    PR_DIRECTORY_OPEN_ERROR = -5988,

    /// Invalid function argument
    PR_INVALID_ARGUMENT_ERROR = -5987,

    /// Network address not available (in use?)
    PR_ADDRESS_NOT_AVAILABLE_ERROR = -5986,

    /// Network address type not supported
    PR_ADDRESS_NOT_SUPPORTED_ERROR = -5985,

    /// Already connected
    PR_IS_CONNECTED_ERROR = -5984,

    /// Network address is invalid
    PR_BAD_ADDRESS_ERROR = -5983,

    /// Local Network address is in use
    PR_ADDRESS_IN_USE_ERROR = -5982,

    /// Connection refused by peer
    PR_CONNECT_REFUSED_ERROR = -5981,

    /// Network address is presently unreachable
    PR_NETWORK_UNREACHABLE_ERROR = -5980,

    /// Connection attempt timed out
    PR_CONNECT_TIMEOUT_ERROR = -5979,

    /// Network file descriptor is not connected
    PR_NOT_CONNECTED_ERROR = -5978,

    /// Failure to load dynamic library
    PR_LOAD_LIBRARY_ERROR = -5977,

    /// Failure to unload dynamic library
    PR_UNLOAD_LIBRARY_ERROR = -5976,

    /// Symbol not found in any of the loaded dynamic libraries
    PR_FIND_SYMBOL_ERROR = -5975,

    /// Insufficient system resources
    PR_INSUFFICIENT_RESOURCES_ERROR = -5974,

    /// A directory lookup on a network address has failed
    PR_DIRECTORY_LOOKUP_ERROR = -5973,

    /// Attempt to access a TPD key that is out of range
    PR_TPD_RANGE_ERROR = -5972,

    /// Process open FD table is full
    PR_PROC_DESC_TABLE_FULL_ERROR = -5971,

    /// System open FD table is full
    PR_SYS_DESC_TABLE_FULL_ERROR = -5970,

    /// Network operation attempted on non-network file descriptor
    PR_NOT_SOCKET_ERROR = -5969,

    /// TCP-specific function attempted on a non-TCP file descriptor
    PR_NOT_TCP_SOCKET_ERROR = -5968,

    /// TCP file descriptor is already bound
    PR_SOCKET_ADDRESS_IS_BOUND_ERROR = -5967,

    /// Access Denied
    PR_NO_ACCESS_RIGHTS_ERROR = -5966,

    /// The requested operation is not supported by the platform
    PR_OPERATION_NOT_SUPPORTED_ERROR = -5965,

    /// The host operating system does not support the protocol requested
    PR_PROTOCOL_NOT_SUPPORTED_ERROR = -5964,

    /// Access to the remote file has been severed
    PR_REMOTE_FILE_ERROR = -5963,

    /// The value requested is too large to be stored in the data buffer provided
    PR_BUFFER_OVERFLOW_ERROR = -5962,

    /// TCP connection reset by peer
    PR_CONNECT_RESET_ERROR = -5961,

    /// Unused
    PR_RANGE_ERROR = -5960,

    /// The operation would have deadlocked
    PR_DEADLOCK_ERROR = -5959,

    /// The file is already locked
    PR_FILE_IS_LOCKED_ERROR = -5958,

    /// Write would result in file larger than the system allows
    PR_FILE_TOO_BIG_ERROR = -5957,

    /// The device for storing the file is full
    PR_NO_DEVICE_SPACE_ERROR = -5956,

    /// Unused
    PR_PIPE_ERROR = -5955,

    /// Unused
    PR_NO_SEEK_DEVICE_ERROR = -5954,

    /// Cannot perform a normal file operation on a directory
    PR_IS_DIRECTORY_ERROR = -5953,

    /// Symbolic link loop
    PR_LOOP_ERROR = -5952,

    /// File name is too long
    PR_NAME_TOO_LONG_ERROR = -5951,

    /// File not found
    PR_FILE_NOT_FOUND_ERROR = -5950,

    /// Cannot perform directory operation on a normal file
    PR_NOT_DIRECTORY_ERROR = -5949,

    /// Cannot write to a read-only file system
    PR_READ_ONLY_FILESYSTEM_ERROR = -5948,

    /// Cannot delete a directory that is not empty
    PR_DIRECTORY_NOT_EMPTY_ERROR = -5947,

    /// Cannot delete or rename a file object while the file system is busy
    PR_FILESYSTEM_MOUNTED_ERROR = -5946,

    /// Cannot rename a file to a file system on another device
    PR_NOT_SAME_DEVICE_ERROR = -5945,

    /// The directory object in the file system is corrupted
    PR_DIRECTORY_CORRUPTED_ERROR = -5944,

    /// Cannot create or rename a filename that already exists
    PR_FILE_EXISTS_ERROR = -5943,

    /// Directory is full.  No additional filenames may be added
    PR_MAX_DIRECTORY_ENTRIES_ERROR = -5942,

    /// The required device was in an invalid state
    PR_INVALID_DEVICE_STATE_ERROR = -5941,

    /// The device is locked
    PR_DEVICE_IS_LOCKED_ERROR = -5940,

    /// No more entries in the directory
    PR_NO_MORE_FILES_ERROR = -5939,

    /// Encountered end of file
    PR_END_OF_FILE_ERROR = -5938,

    /// Seek error
    PR_FILE_SEEK_ERROR = -5937,

    /// The file is busy
    PR_FILE_IS_BUSY_ERROR = -5936,

    /// The I/O operation was aborted
    PR_OPERATION_ABORTED_ERROR = -5935,

    /// Operation is still in progress (probably a non-blocking connect)
    PR_IN_PROGRESS_ERROR = -5934,

    /// Operation has already been initiated (probably a non-blocking connect)
    PR_ALREADY_INITIATED_ERROR = -5933,

    /// The wait group is empty
    PR_GROUP_EMPTY_ERROR = -5932,

    /// Object state improper for request
    PR_INVALID_STATE_ERROR = -5931,

    /// Network is down
    PR_NETWORK_DOWN_ERROR = -5930,

    /// Socket shutdown
    PR_SOCKET_SHUTDOWN_ERROR = -5929,

    /// Connection aborted
    PR_CONNECT_ABORTED_ERROR = -5928,

    /// Host is unreachable
    PR_HOST_UNREACHABLE_ERROR = -5927,

    /// The library is not loaded
    PR_LIBRARY_NOT_LOADED_ERROR = -5926,

    /// The one-time function was previously called and failed. Its error code is no longer available
    PR_CALL_ONCE_ERROR = -5925,

    /// Placeholder for the end of the list
    PR_MAX_ERROR = -5924,
}

fn get_error_code() -> PRError
{
    let code = unsafe { PR_GetError() };
    FromPrimitive::from_i32(code).unwrap_or(UNKNOWN)
}

pub fn get_error_text() -> String
{
    let len = unsafe { PR_GetErrorTextLength() };
    if len == 0 { return "NSPR did not set an error message".to_string(); }
    let mut res = Vec::with_capacity(len as uint);
    unsafe
    {
        let actual_len = PR_GetErrorText(res.as_mut_ptr());
        res.set_len(actual_len as uint);
    }
    match String::from_utf8(res)
    {
        Ok(string) => format!("{1} ({0})", get_error_code(), string),
        Err(..) => "Error message was invalid UTF-8".to_string(),
    }
}

#[link(name="nspr4")]
extern "C"
{
    pub fn PR_Init(_type: PRThreadType, priority: PRThreadPriority,
                   maxPTDs: c_uint);
    pub fn PR_Cleanup() -> PRStatus;
    fn PR_GetError() -> i32;
    fn PR_GetErrorTextLength() -> i32;
    fn PR_GetErrorText(text: *mut u8) -> i32;
}
