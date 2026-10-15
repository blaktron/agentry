-- +goose Up
-- Platform trust & safety staff flag. A hosted deployment provisions staff
-- out of band; self-host: the instance admin. Kept a simple column.
ALTER TABLE users ADD COLUMN platform_staff boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE users DROP COLUMN platform_staff;
