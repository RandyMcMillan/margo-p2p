use gnostr::hash;

fn main() {
    let data = b"gnostr test via margo registry";
    let digest = hash::hash_string(data);
    println!("gnostr hash: {digest}");
    println!("test-consumer: gnostr loaded from margo registry");
}
