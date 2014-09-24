extern crate nss;

use nss::crypto::symm;

fn main()
{
    nss::init().unwrap();

    let mut crypt = symm::Crypter::new(symm::AES_128_CBC, true).unwrap();
    let key : &[u8] = [0xe8, 0xa7, 0x7c, 0xe2, 0x05, 0x63, 0x6a, 0x31,0,0,0,0,0,0,0,0];
    let iv : &[u8] = [0xe4, 0xbb, 0x3b, 0xd3, 0xc3, 0x71, 0x2e, 0x58,0,0,0,0,0,0,0,0];
    let message = b"Encrypt me!\0";

    println!("input:     {}", String::from_utf8_lossy(message));

    crypt.init(symm::Encrypt, key, iv).unwrap();
    let mut out = crypt.update(message).unwrap();
    out.extend(crypt.final().unwrap().into_iter());

    print!("encrypted:");
    for b in out.iter()
    {
        print!(" {:02x}", *b);
    }
    println!("");

    crypt.init(symm::Decrypt, key, iv).unwrap();
    let mut dec = crypt.update(out.as_slice()).unwrap();
    dec.extend(crypt.final().unwrap().into_iter());

    println!("decrypted: {}", String::from_utf8_lossy(dec.as_slice()));

    let _ = nss::close();
}
