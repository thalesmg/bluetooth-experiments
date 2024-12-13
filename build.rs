fn main() {
    println!("cargo:rustc-link-lib=bluetooth");

    const HEADER_FILE: &str = "src/bluetooth.h";
    let bindings = bindgen::Builder::default()
        .header(HEADER_FILE)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Failed to generate bindings for bluez");

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Failed to write bindings for libbluetooth");
}
