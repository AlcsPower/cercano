-- Schema for Cercano/RustDesk server peer database
CREATE TABLE IF NOT EXISTS peer (
    guid BLOB PRIMARY KEY NOT NULL,
    id VARCHAR(100) NOT NULL,
    uuid BLOB NOT NULL,
    pk BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT(CURRENT_TIMESTAMP),
    user BLOB,
    status TINYINT,
    note VARCHAR(300),
    info TEXT NOT NULL
) WITHOUT ROWID;
CREATE UNIQUE INDEX IF NOT EXISTS index_peer_id ON peer (id);
CREATE INDEX IF NOT EXISTS index_peer_user ON peer (user);
CREATE INDEX IF NOT EXISTS index_peer_created_at ON peer (created_at);
CREATE INDEX IF NOT EXISTS index_peer_status ON peer (status);
