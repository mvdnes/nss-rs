#![allow(unstable)]

extern crate "rustc-serialize" as serialize;
extern crate nss;

use nss::crypto::pkey;
use serialize::base64::FromBase64;

static PUB_BASE64 : &'static [u8] = b"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL3F6TIc3JEYsugo+a2fPU3W+Epv/FeIX21DC86WYnpFtW4srFtz2oNUzyLUzDHZdb+k//8dcT3IAOzUUi3R2eMCAwEAAQ==";
static PRIV_BASE64 : &'static [u8] = b"MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAvcXpMhzckRiy6Cj5rZ89Tdb4Sm/8V4hfbUMLzpZiekW1biysW3Pag1TPItTMMdl1v6T//x1xPcgA7NRSLdHZ4wIDAQABAkEAjh8+4qncwcmGivnM6ytbpQT+k/jEOeXG2bQhjojvnXN3FazGCEFXvpuIBcJVfaIJS9YBCMOzzrAtO0+k2hWnOQIhAOC4NVbo8FQhZS4yXM1M86kMl47FA9ui//OUfbhlAdw1AiEA2DBmIXnsboKB+OHver69p0gNeWlvcJc9bjDVfdLVsLcCIQCPtV3vGYJv2vdwxqZQaHC+YB4gIGAqOqBCbmjD3lyFLQIgA+VTYdUNoqwtZWvE4gRf7IzK2V5CCNhg3gR5RGwxN58CIGCcafoRrUKsM66ISg0ITI04G9V/w+wMx91wjEEB+QBz";

fn doit() -> nss::result::NSSResult<()>
{
    let pub_der = PUB_BASE64.from_base64().unwrap();
    let priv_der = PRIV_BASE64.from_base64().unwrap();

    let pubkey = try!(pkey::RSAPublicKey::load(pub_der.as_slice()));
    let enc = try!(pubkey.encrypt(pkey::RSAPadding::OAEP_MGF1_SHA1, b"Encrypt Me!"));
    print!("Encoded:");
    for b in enc.iter()
    {
        print!(" {:02x}", *b);
    }
    println!("");

    let privkey = try!(pkey::RSAPrivateKey::load(priv_der.as_slice()));
    let dec = try!(privkey.decrypt(pkey::RSAPadding::OAEP_MGF1_SHA1, enc.as_slice()));
    println!("Decoded: {}", String::from_utf8(dec).unwrap());

    Ok(())
}

fn main()
{
    println!("{:?}", doit());
    let _ = nss::close();
}
