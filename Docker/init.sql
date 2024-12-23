CREATE DATABASE postgresauthentication;
GRANT ALL PRIVILEGES ON DATABASE postgresauthentication TO postgres;
\c postgresauthentication;
CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    is_guest BOOLEAN NOT NULL,
    is_superuser BOOLEAN NOT NULL,
    username VARCHAR(150) NOT NULL,
    firstname VARCHAR(254) NULL,
    lastname VARCHAR(254) NULL,
    email VARCHAR(254) NULL,
    password VARCHAR(254) NOT NULL
    );