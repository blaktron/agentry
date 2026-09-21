-- +goose Up
-- The SAML replay cache and request tracker, shared by every API replica
-- (agentry#414). Each was a set in one process's memory: an assertion
-- consumed by one replica was accepted again by the next, and a login
-- started on one replica could not be completed on another. Both are
-- TTL sets keyed by an opaque id, and the database every deployment has
-- is where every replica can see them; a Redis-backed implementation
-- stays possible behind the same interfaces. Expired rows are swept by
-- the writers themselves, now and then, so the sets stay the size of
-- what is live — minutes of assertions.
-- An id is the identity provider's, so its length is bounded here: a
-- longer one is refused before it is stored, and the writers refuse it
-- before they ask.
CREATE TABLE saml_consumed_assertions (
  id         text PRIMARY KEY CHECK (length(id) <= 1024),
  expires_at timestamptz NOT NULL
);
CREATE INDEX saml_consumed_assertions_expires_at_idx ON saml_consumed_assertions (expires_at);

CREATE TABLE saml_requests (
  id         text PRIMARY KEY CHECK (length(id) <= 1024),
  expires_at timestamptz NOT NULL
);
CREATE INDEX saml_requests_expires_at_idx ON saml_requests (expires_at);

-- +goose Down
DROP TABLE IF EXISTS saml_requests;
DROP TABLE IF EXISTS saml_consumed_assertions;
