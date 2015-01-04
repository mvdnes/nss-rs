use std::fmt;

pub type NSSResult<T> = Result<T, NSSError>;

#[derive(Copy)]
pub enum NSSError
{
    /// An error generated by NSPR or NSS
    NSS(i32),
}

impl fmt::Show for NSSError
{
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error>
    {
        match *self
        {
            NSSError::NSS(code) => {
                match ::ffi::nspr::get_error_message(code)
                {
                    Some(message) => {
                        let message_str = String::from_utf8_lossy(message.as_bytes());
                        formatter.write_str(&*message_str)
                    },
                    None => write!(formatter, "Unknown error {}", code),
                }
            },
        }
    }
}
