
fn main() {
    if std::is_x86_feature_detected!("aes") {
        println!("cargo:rustc-cfg=rcrypto_aes=\"support\"");
    }

    if std::is_x86_feature_detected!("sse2") {
        println!("cargo:rustc-cfg=rcrypto_sse2=\"support\"");
    }

    if std::is_x86_feature_detected!("sha") {
        println!("cargo:rustc-cfg=rcrypto_sha=\"support\"");
    }
}

