CREATE TABLE user (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  profile_pic TEXT NOT NULL,
  refresh_token TEXT,
  access_token TEXT,
  expiration INTEGER,
  uuid TEXT,
  active INTEGER
);
