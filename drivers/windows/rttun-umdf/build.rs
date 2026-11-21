fn main() -> Result<(), wdk_build::ConfigError> {
    let status = wdk_build::configure_wdk_binary_build();
    let root = std::env::var("WDKContentRoot")
        .unwrap_or_else(|_| r"C:\Program Files (x86)\Windows Kits\10".to_string());
    let lib = std::path::Path::new(&root).join(r"Lib\10.0.26100.0\um\x64\netcx\umdf\adapter\2.5");
    if lib.is_dir() {
        println!("cargo:rustc-link-search=native={}", lib.display());
    }
    status
}
