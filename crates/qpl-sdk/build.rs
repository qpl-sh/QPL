fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = "../../proto";
    let out_dir = "src/generated";

    // Ensure the output directory exists
    std::fs::create_dir_all(out_dir)?;

    // Only compile protos if protoc is available
    // Service stubs work without generated code; gRPC clients will be
    // wired when qpl-node (Phase 4) provides the server implementation.
    let result = tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .out_dir(out_dir)
        .compile_protos(
            &[
                &format!("{}/qpl_operator.proto", proto_dir),
                &format!("{}/qpl_coordination.proto", proto_dir),
            ],
            &[proto_dir],
        );

    match result {
        Ok(_) => println!("cargo:warning=QPL SDK: proto clients generated successfully"),
        Err(e) => {
            println!("cargo:warning=QPL SDK: skipping proto compilation ({e}). Install protoc to generate gRPC clients.");
            // Write empty module so `mod generated` compiles
            std::fs::write(format!("{}/mod.rs", out_dir), "// Auto-generated — install protoc to regenerate\n")?;
        }
    }

    Ok(())
}
