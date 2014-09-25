use sync::mutex::{StaticMutex, MUTEX_INIT};
use ffi::{nss, nspr};

static mut INITLOCK: StaticMutex = MUTEX_INIT;
static mut INIT_STATUS : bool = false;

pub fn init() -> ::NSSResult<()>
{
    unsafe
    {
        let _guard = INITLOCK.lock();
        if INIT_STATUS == true { return Ok(()); }

        nspr::PR_Init(nspr::PR_SYSTEM_THREAD, nspr::PR_PRIORITY_NORMAL, 0);
        match nss::NSS_NoDB_Init(::std::ptr::null_mut()).to_result()
        {
            Ok(..) => { INIT_STATUS = true; Ok(()) },
            Err(e) => Err(e),
        }
    }
}

pub fn close() -> ::NSSResult<()>
{
    unsafe
    {
        let _guard = INITLOCK.lock();
        if INIT_STATUS == false { return Ok(()); }

        match nss::NSS_Shutdown().to_result()
        {
            Ok(..) =>
            {
                nspr::PR_Cleanup();
                INIT_STATUS = false;
                Ok(())
            },
            Err(e) => Err(e),
        }
    }
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
