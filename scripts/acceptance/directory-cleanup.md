# Directory CI resources

The directory acceptance scripts retain their normal `EXIT` cleanup with
`docker rm -fv`. On Actions they also label **every** container and network
with `io.agentry.ci.directory=true`, `.job` (repository/run/attempt/job), and
`.expires-at` (Unix seconds, 35 minutes after the script starts). Recreated
workers retain the same labels and deadline. Local runs are not labeled.

Each directory job has a timeout of at most 25 minutes and an `if: always()`
step that runs `python3 scripts/acceptance/directory-cleanup.py --job`.
It removes only that job's labeled resources, containers before networks,
including anonymous volumes. No name-prefix or daemon-wide prune is used.

Cancellation can kill both the script and its cleanup step. Both Linux runner
hosts therefore install this same Python script as
`/usr/local/sbin/runner-directory-cleanup`, keeping its deployed source at
`~/runner/directory-cleanup.py`. `/etc/cron.d/runner-directory-cleanup` runs:

```cron
*/10 * * * * root /usr/local/sbin/runner-directory-cleanup --expired 2>&1 | /usr/bin/logger -t runner-directory-cleanup
```

The expiry sweep ignores unlabeled resources, absent job labels and malformed
deadlines. It removes a killed stack by 45 minutes after script start,
without needing host-wide idle time or a GitHub token. A live job's maximum
25-minute timeout precedes expiry by ten minutes. Increasing a directory
job's timeout requires increasing this deadline and retaining the one-hour
cleanup bound (agentry#800). `--expired --dry-run` previews the sweep.

After a cleanup change, install the reviewed script on **both** runner hosts
with `sudo install -m 0755 ~/runner/directory-cleanup.py /usr/local/sbin/runner-directory-cleanup`.
The separate cron does not change the hourly cache trim or touch Go caches.
Run `python3 scripts/acceptance/directory-cleanup-selftest.py` against Docker:
it proves cancellation ownership, expiry, concurrent-job isolation, network
cleanup and anonymous-volume removal. CI runs it in `directory-email`.
