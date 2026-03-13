fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = &[
        "../../proto/rok/keys.proto",
        "../../proto/rok/envelope.proto",
        "../../proto/rok/keyring.proto",
        "../../proto/rok/access.proto",
    ];

    let include_dirs = &["../../proto"];

    prost_build::Config::new()
        .out_dir("src/generated")
        .compile_protos(proto_files, include_dirs)?;

    // Re-run if any proto file changes
    for proto in proto_files {
        println!("cargo:rerun-if-changed={}", proto);
    }

    Ok(())
}
