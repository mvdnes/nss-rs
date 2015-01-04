use std::sync::atomic::{AtomicBool, ATOMIC_BOOL_INIT, Ordering};
use result::NSSResult;
use ffi::{nss, nspr};

static NSSBUSY: AtomicBool = ATOMIC_BOOL_INIT;
static NSSINIT: AtomicBool = ATOMIC_BOOL_INIT;

pub fn init() -> NSSResult<()>
{
    while NSSBUSY.compare_and_swap(false, true, Ordering::SeqCst) != false {};

    let result =
    if NSSINIT.load(Ordering::SeqCst) == false {
        unsafe { nspr::PR_Init(nspr::PRThreadType::PR_SYSTEM_THREAD, nspr::PRThreadPriority::PR_PRIORITY_NORMAL, 0) };
        match unsafe { nss::NSS_NoDB_Init(::std::ptr::null_mut()).to_result() }
        {
            Ok(..) => {
                NSSINIT.store(true, Ordering::SeqCst);
                Ok(())
            },
            Err(e) => Err(e),
        }
    }
    else {
        Ok(())
    };

    NSSBUSY.store(false, Ordering::SeqCst);

    result
}

pub fn close() -> NSSResult<()>
{
    while NSSBUSY.compare_and_swap(false, true, Ordering::SeqCst) != false {};

    let result =
    if NSSINIT.load(Ordering::SeqCst) == true {
        match unsafe { nss::NSS_Shutdown().to_result() }
        {
            Ok(..) => {
                unsafe { nspr::PR_Cleanup() };
                NSSINIT.store(false, Ordering::SeqCst);
                Ok(())
            },
            Err(e) => Err(e),
        }
    }
    else {
        Ok(())
    };

    NSSBUSY.store(false, Ordering::SeqCst);

    result
}

#[cfg(test)]
mod test
{
    #[test]
    fn init()
    {
        super::init().unwrap();
    }
}
