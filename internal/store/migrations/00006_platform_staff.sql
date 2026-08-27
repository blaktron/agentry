-- +goose Up
-- Platform trust & safety staff flag (§12.2 last row). SaaS provisions staff
-- out of band; self-host: the instance admin. Kept a simple column in v1.
ALTER TABLE users ADD COLUMN platform_staff boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE users DROP COLUMN platform_staff;
