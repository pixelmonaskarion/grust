fn main() {
    protobuf_codegen::Codegen::new()
    // Use `protoc` parser, optional.
    .protoc()
    // All inputs and imports from the inputs must reside in `includes` directories.
    .includes(&["src/protos"])
    // Inputs must reside in some of include paths.
    .input("src/protos/authentication.proto")
    .input("src/protos/client.proto")
    .input("src/protos/config.proto")
    .input("src/protos/conversations.proto")
    .input("src/protos/events.proto")
    .input("src/protos/rpc.proto")
    .input("src/protos/settings.proto")
    .input("src/protos/ukey.proto")
    .input("src/protos/pblite.proto")
    .input("src/protos/util.proto")
    // Specify output directory relative to Cargo output directory.
    .cargo_out_dir("protos")
    .run_from_script();
}