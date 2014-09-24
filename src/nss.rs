use std::sync::atomic;
use ffi::{nss, nspr};

static mut NSS_INITED : atomic::AtomicBool = atomic::INIT_ATOMIC_BOOL;

pub fn init() -> Result<(), String>
{
    unsafe
    {
        if NSS_INITED.compare_and_swap(false, true, atomic::SeqCst) == false
        {
            nspr::PR_Init(nspr::PR_USER_THREAD, nspr::PR_PRIORITY_NORMAL, 0);
            try!(nss::NSS_NoDB_Init(::std::ptr::null_mut()).to_result());
        }
        else
        {
            warn!("init called in initialized state");
        }
        Ok(())
    }
}

pub fn close() -> Result<(), String>
{
    unsafe
    {
        if NSS_INITED.compare_and_swap(true, false, atomic::SeqCst) == true
        {
            try!(nss::NSS_Shutdown().to_result());
            nspr::PR_Cleanup();
        }
        else
        {
            warn!("close called in non-initialized state");
        }
        Ok(())
    }
}

#[cfg(test)]
mod test
{
    #[test]
    fn init_and_close()
    {
        super::init().unwrap();
        super::close().unwrap();
    }
}
