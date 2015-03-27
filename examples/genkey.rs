extern crate nss;

use std::io::prelude::*;
use nss::crypto::pkey;

fn main()
{
    let args: Vec<_> = std::env::args().collect();
    if args.len() <= 1
    {
        print_usage(&*args[0]);
        return
    }

    let mut privkey = pkey::RSAPrivateKey::gen(2048).unwrap();
    let pubkey = privkey.get_public().unwrap();

    let pub_der = pubkey.save().unwrap();
    let priv_der = privkey.save().unwrap();

    let priv_path = std::path::Path::new(&*args[1]);
    let pub_path = priv_path.with_extension("pub");

    let mut priv_file = std::fs::File::create(&priv_path).unwrap();
    let mut pub_file = std::fs::File::create(&pub_path).unwrap();

    println!("pub : {:?}", pub_file.write(&*pub_der));
    println!("priv: {:?}", priv_file.write(&*priv_der));
    let _ = nss::close();
}

fn print_usage(name: &str)
{
    println!("Usage: {} <filename>", name);
}
