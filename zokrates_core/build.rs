#[cfg(feature = "libsnark")]
extern crate cc;
#[cfg(feature = "libsnark")]
extern crate cmake;
#[cfg(feature = "libsnark")]
extern crate git2;

fn main() {
    #[cfg(feature = "libsnark")]
    {
        use git2::{Oid, Repository, ResetType};
        use std::env;
        use std::fs::remove_dir;
        use std::path::PathBuf;
        use std::process::Command;

        // fetch libsnark and libsnark-supercop source

        const LIBSNARK_URL: &'static str = "https://github.com/second-state/libsnark.git";
        const LIBSNARK_COMMIT: &'static str = "3dbd8e792d68005654817638e334e3f59f08ffd7";
        const SUPERCOP_URL: &'static str = "https://github.com/second-state/libsnark-supercop.git";
        const SUPERCOP_COMMIT: &'static str = "f0714c545abb88ae42657f1960fc395250f058dd";

        let libsnark_source_path = &PathBuf::from(env::var("OUT_DIR").unwrap()).join("LIBSNARK");
        let supercop_source_path = &PathBuf::from(env::var("OUT_DIR").unwrap()).join("libsnark-supercop");

        // Cloning to libsnark

        let repo = Repository::open(libsnark_source_path).unwrap_or_else(|_| {
            remove_dir(libsnark_source_path).ok();
            Repository::clone(LIBSNARK_URL, libsnark_source_path).unwrap()
        });

        let commit = Oid::from_str(LIBSNARK_COMMIT).unwrap();
        let commit = repo.find_commit(commit).unwrap();

        repo.reset(&commit.as_object(), ResetType::Hard, None)
            .unwrap();

        for mut s in repo.submodules().unwrap() {
            s.update(true, None).unwrap();
        }

        // Cloning to libsnark-supercop

        let repo = Repository::open(supercop_source_path).unwrap_or_else(|_| {
            remove_dir(supercop_source_path).ok();
            Repository::clone(SUPERCOP_URL, supercop_source_path).unwrap()
        });

        let commit = Oid::from_str(SUPERCOP_COMMIT).unwrap();
        let commit = repo.find_commit(commit).unwrap();

        repo.reset(&commit.as_object(), ResetType::Hard, None)
            .unwrap();


        // build libsnark

        let libsnark = cmake::Config::new(libsnark_source_path)
            .define("WITH_PROCPS", "OFF")
            .define("CURVE", "ALT_BN128")
            .define("USE_PT_COMPRESSION", "OFF")
            .define("MONTGOMERY_OUTPUT", "ON")
            .define("BINARY_OUTPUT", "ON")
            .build();

        // build supercop

        Command::new("sh")
                .arg("./do_enable_pic")
                .current_dir(&supercop_source_path)
                .spawn()
                .expect("Supercop build failed");

        // build backends

        cc::Build::new()
            .cpp(true)
            .debug(cfg!(debug_assertions))
            .flag("-std=c++11")
            .include(libsnark_source_path)
            .include(libsnark_source_path.join("depends/libff"))
            .include(libsnark_source_path.join("depends/libfqfft"))
            .include(supercop_source_path.join("include"))
            .define("CURVE_ALT_BN128", None)
            .file("lib/util.cpp")
            .file("lib/gm17.cpp")
            .file("lib/pghr13.cpp")
            .file("lib/bbfr15.cpp")
            .file("lib/prf/aes_ctr_prf.tcc")
            .file("lib/signature/ed25519_signature.tcc")
            .compile("libwraplibsnark.a");

        println!(
            "cargo:rustc-link-search=native={}",
            libsnark.join("lib").display()
        );

         println!(
            "cargo:rustc-link-search=native={}",
            supercop_source_path.join("lib").display()
        );

        println!("cargo:rustc-link-lib=gmp");
        println!("cargo:rustc-link-lib=gmpxx");
        println!("cargo:rustc-link-lib=static=supercop");

        #[cfg(debug_assertions)]
        {
            println!("cargo:rustc-link-lib=static=snarkd");
            println!("cargo:rustc-link-lib=static=ffd");
        }
        #[cfg(not(debug_assertions))]
        {
            println!("cargo:rustc-link-lib=static=snark");
            println!("cargo:rustc-link-lib=static=ff");
        }
    }
}
