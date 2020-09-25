
fn cvt_bytes_to_str(b: &[u8]) -> String {
    let mut s= String::new();
    for &ele in b.iter() {
        let e = format!("{:02X}", ele);
        s.push_str(e.as_str());
    }
    s
}

