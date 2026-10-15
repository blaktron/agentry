-- +goose Up
-- The organization's logo: the key of the re-encoded raster in the
-- deployment's object store, under the organization. NULL means none. The
-- bytes are never the upload's — the core decodes and re-encodes every logo
-- through the image proxy's path, and the key carries the digest of what is
-- served, so the URL a client renders changes when the logo does and a cache
-- holds the old one no longer than the old URL is linked.
ALTER TABLE orgs ADD COLUMN logo_object_key text;

-- +goose Down
ALTER TABLE orgs DROP COLUMN logo_object_key;
