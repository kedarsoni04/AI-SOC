-- PostgreSQL initialization script
-- Run once on first startup

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- for text search

-- Set timezone
SET timezone = 'UTC';
