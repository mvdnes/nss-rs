extern crate nss;

use nss::crypto::symm;

fn doit() -> Result<(), String>
{
    let mut crypt = try!(symm::Crypter::new(symm::AES_128_CBC, true));
    let key : &[u8] = [0xe8, 0xa7, 0x7c, 0xe2, 0x05, 0x63, 0x6a, 0x31,0,0,0,0,0,0,0,0];
    let iv : &[u8] = [0xe4, 0xbb, 0x3b, 0xd3, 0xc3, 0x71, 0x2e, 0x58,0,0,0,0,0,0,0,0];
    let message = b"Encrypt me!\0";

    println!("input:     {}", String::from_utf8_lossy(message));

    try!(crypt.init(symm::Encrypt, key, iv));
    let mut out = try!(crypt.update(message));
    out.extend(try!(crypt.final()).into_iter());

    print!("encrypted:");
    for b in out.iter()
    {
        print!(" {:02x}", *b);
    }
    println!("");

    try!(crypt.init(symm::Decrypt, key, iv));
    let mut dec = try!(crypt.update(out.as_slice()));
    dec.extend(try!(crypt.final()).into_iter());

    println!("decrypted: {}", String::from_utf8_lossy(dec.as_slice()));

    Ok(())
}

fn main()
{
    nss::init().unwrap();
    let result = doit();
    let message = result.err().unwrap_or("Ok!".to_string());
    println!("{}", message);
    let _ = nss::close();
}
