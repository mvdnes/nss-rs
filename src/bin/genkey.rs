#![allow(unstable)]

extern crate nss;

use nss::crypto::pkey;

fn main()
{
    let args = std::os::args();
    if args.len() <= 1
    {
        print_usage(args[0].as_slice());
        return
    }

    let privkey = pkey::RSAPrivateKey::gen(2048).unwrap();
    let pubkey = privkey.get_public().unwrap();

    let pub_der = pubkey.save().unwrap();
    let priv_der = privkey.save().unwrap();

    let priv_path = Path::new(args[1].as_slice());
    let pub_path = priv_path.with_extension("pub");

    let mut priv_file = std::io::File::create(&priv_path).unwrap();
    let mut pub_file = std::io::File::create(&pub_path).unwrap();

    println!("pub : {:?}", pub_file.write(pub_der.as_slice()));
    println!("priv: {:?}", priv_file.write(priv_der.as_slice()));
    let _ = nss::close();
}

fn print_usage(name: &str)
{
    println!("Usage: {} <filename>", name);
}
