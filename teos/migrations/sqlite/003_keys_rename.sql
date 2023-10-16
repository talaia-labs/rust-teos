-- Rename `key` to `secret_key` as the word `key` is reserved in some databases.
ALTER TABLE keys RENAME key TO secret_key;
