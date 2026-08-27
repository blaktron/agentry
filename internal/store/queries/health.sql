-- Health/diagnostic queries. Real domain queries land with M1 (WG-B).

-- name: Now :one
SELECT now()::timestamptz AS server_time;
