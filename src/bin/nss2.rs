/*
 * Written like the example on:
 * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_Sample_Code/NSS_Sample_Code_sample2
 */

extern crate nss;

use nss::crypto::symm;

fn doit() -> nss::result::NSSResult<()>
{
    let mut crypt = try!(symm::Crypter::new(symm::DES_CBC, true));

    let key : &[u8] = [0xe8, 0xa7, 0x7c, 0xe2, 0x05, 0x63, 0x6a, 0x31];
    let iv : &[u8] = [0xe4, 0xbb, 0x3b, 0xd3, 0xc3, 0x71, 0x2e, 0x58];
    let message = b"Encrypt me!\0";

    println!("Clear Data: {}", String::from_utf8_lossy(message));

    try!(crypt.init(symm::Encrypt, key, iv));
    let mut out = try!(crypt.update(message));
    out.extend(try!(crypt.finalize()).into_iter());

    print!("Encrypted Data:");
    for b in out.iter()
    {
        print!(" {:02x}", *b);
    }
    println!("");

    try!(crypt.init(symm::Decrypt, key, iv));
    let mut dec = try!(crypt.update(out.as_slice()));
    dec.extend(try!(crypt.finalize()).into_iter());

    println!("Decrypted Data: {}", String::from_utf8_lossy(dec.as_slice()));

    Ok(())
}

fn main()
{
    nss::init().unwrap();
    let result = doit();
    match result.err()
    {
        Some(m) => println!("{}", m),
        None => {},
    }
    let _ = nss::close();
}
