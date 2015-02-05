#![feature(core)]

/*
 * Written like the example on:
 * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_Sample_Code/NSS_Sample_Code_sample2
 */

extern crate nss;

use nss::crypto::symm;

fn doit() -> nss::result::NSSResult<()>
{
    let key : &[u8] = &[0xe8, 0xa7, 0x7c, 0xe2, 0x05, 0x63, 0x6a, 0x31];
    let iv : &[u8] = &[0xe4, 0xbb, 0x3b, 0xd3, 0xc3, 0x71, 0x2e, 0x58];
    let message = b"Encrypt me!\0";

    println!("Clear Data: {}", String::from_utf8_lossy(message));

    let mut crypt = try!(symm::Crypter::new(symm::Kind::DES_CBC_PAD, symm::Mode::Encrypt, key, iv));
    let out = try!(crypt.finalize(message));

    print!("Encrypted Data:");
    for b in out.iter()
    {
        print!(" {:02x}", *b);
    }
    println!("");

    let mut crypt = try!(symm::Crypter::new(symm::Kind::DES_CBC_PAD, symm::Mode::Decrypt, key, iv));
    let dec = try!(crypt.finalize(&*out));

    println!("Decrypted Data: {}", String::from_utf8_lossy(&*dec));

    Ok(())
}

fn main()
{
    nss::init().unwrap();
    let result = doit();
    match result.err()
    {
        Some(m) => println!("{:?}", m),
        None => {},
    }
    let _ = nss::close();
}
