fn main() {
    hbb_common::gen_version();
    let db_path = std::path::Path::new("db_v2.sqlite3");
    if !db_path.exists() {
        if let Ok(schema) = std::fs::read_to_string("schema.sql") {
            let _ = std::process::Command::new("sqlite3")
                .arg("db_v2.sqlite3")
                .arg(&schema)
                .status();
        }
    }
}
