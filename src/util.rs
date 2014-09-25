#![macro_escape]

macro_rules! try_ptr(
    ($e:expr) =>
        ({
            if $e.is_null()
            {
                return Err(::ffi::nspr::get_error_code());
            }
            $e
        })
)
