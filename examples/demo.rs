use sealable::prelude::*;

fn main() -> Result<(), sealable::Error> {
    let sealed = DefaultSealedBox::encrypt("my-password", b"hello world")?;
    println!("Sealed: {}", sealed);
    let plaintext = DefaultSealedBox::decrypt("my-password", &sealed)?;
    println!("Decrypted: {}", String::from_utf8_lossy(&plaintext));
    Ok(())
}
