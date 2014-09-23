use std::sync::atomic;
use ffi::{nss, nspr};

static mut NSS_INITED : atomic::AtomicBool = atomic::INIT_ATOMIC_BOOL;

pub fn init()
{
    unsafe
    {
        if NSS_INITED.compare_and_swap(false, true, atomic::SeqCst) == false
        {
            nspr::PR_Init(nspr::PR_USER_THREAD, nspr::PR_PRIORITY_NORMAL, 0);
            nss::NSS_NoDB_Init(::std::ptr::null_mut());
        }
        else
        {
            warn!("init called in initialized state");
        }
    }
}

pub fn close()
{
    unsafe
    {
        if NSS_INITED.compare_and_swap(true, false, atomic::SeqCst) == true
        {
            nss::NSS_Shutdown();
            nspr::PR_Cleanup();
        }
        else
        {
            warn!("close called in non-initialized state");
        }
    }
}

#[cfg(test)]
mod test
{
    #[test]
    fn init_and_close()
    {
        super::init();
        super::close();
    }
}
