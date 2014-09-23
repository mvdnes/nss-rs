extern crate nss;

use nss::crypto::symm;

fn main()
{
    nss::init();

    let crypt = symm::Crypter::new(symm::AES_128_CBC, true);

    nss::close();
}
