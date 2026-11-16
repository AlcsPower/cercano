fn main() {
    let protos_dir = std::path::Path::new("src/protos");
    if !protos_dir.exists() {
        std::fs::create_dir_all(protos_dir).unwrap();
    }
    let mod_rs = protos_dir.join("mod.rs");
    if !mod_rs.exists() {
        std::fs::write(&mod_rs, "include!(concat!(env!(\"OUT_DIR\"), \"/protos/mod.rs\"));\n").unwrap();
    }

    let out_dir = format!("{}/protos", std::env::var("OUT_DIR").unwrap());

    std::fs::create_dir_all(&out_dir).unwrap();

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(out_dir)
        .inputs(["protos/rendezvous.proto", "protos/message.proto"])
        .include("protos")
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run()
        .expect("Codegen failed.");
}
