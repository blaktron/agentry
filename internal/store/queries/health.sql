-- Health/diagnostic queries.

-- name: Now :one
SELECT now()::timestamptz AS server_time;
