use std::fs;
use std::path::PathBuf;

use cc;

// Slice with windows specific files to be filtered out
const DIFF: [&str; 3] = ["evercrypt_bcrypt.c", "EverCrypt.c", "evercrypt_openssl.c"];

fn main() {
    let hacl_src = PathBuf::from("hacl-star/dist");
    let kremlin = hacl_src.join("kremlin");
    let c89 = hacl_src.join("c89-compatible");

    let mut builder = cc::Build::new();

    builder
        .warnings_into_errors(true)
        .static_flag(true)
        .flag("-std=gnu11")
        .flag("-Wno-unused-variable")
        .flag("-Wno-unused-but-set-variable")
        .flag("-Wno-unused-parameter")
        .flag("-g")
        .flag("-fwrapv")
        .flag("-march=native")
        .flag("-mtune=native");

    builder
        .define("_BSD_SOURCE", None)
        .define("_DEFAULT_SOURCE", None);

    #[cfg(target_arch = "x86_64")]
    builder.define("EVERCRYPT_TARGETCONFIG_X64", None);

    builder
        .include(&c89)
        .include(&c89.join("include"))
        .include(&kremlin.join("include"))
        .include(&kremlin.join("kremlib/dist/minimal"));

    let mut files = Vec::new();
    let mut add_files = |suffix: &str| {
        for file in fs::read_dir(&c89).unwrap() {
            let file = file.unwrap();
            let name = file.file_name().into_string().unwrap();
            // As we are only targeting linux, remove windows specific files
            if DIFF.contains(&name.as_str()) {
                continue;
            }

            if name.ends_with(suffix) {
                files.push(file.path());
            }
        }
    };

    ["-linux.S", ".c"]
        .iter()
        .for_each(|suffix| add_files(suffix));

    builder.files(files);
    dbg!(&builder);
    builder.compile("libevercrypt.a");
}
