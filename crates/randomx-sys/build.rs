fn main() {
    let dst = cmake::Config::new("randomx")
        .define("ARCH", "native")
        .build_target("randomx")
        .build();

    println!("cargo:rustc-link-search=native={}/build", dst.display());
    println!("cargo:rustc-link-lib=static=randomx");
    println!("cargo:rustc-link-lib=dylib=stdc++");
}
