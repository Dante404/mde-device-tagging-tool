# Design decisions

## Safety model

The tool uses independent controls so that one accidental parameter change is insufficient
to silently modify devices:

1. `DryRun` is a Boolean parameter whose default value is `true`.
2. Live mode still passes every planned change through PowerShell `ShouldProcess`.
3. Ambiguous hostname matches are skipped unless the operator explicitly selects the newest
   record or narrows the match with a domain suffix.
4. Idempotency checks skip additions that already exist and removals that are already absent.
5. Every input produces a result record, including failures and non-actions.

## Authentication

The project uses a public-client application and delegated device-code authentication. The
small protocol implementation follows Microsoft's documented `/devicecode` and `/token`
exchange, honors the server's polling interval, handles pending and slow-down responses, and
keeps the returned access token only in memory. It requests no `offline_access` scope and
therefore does not receive or persist a refresh token.

This keeps the sample dependency-free and auditable. A production application that needs a
durable token cache or richer interactive behavior should use the supported MSAL.NET library
instead of extending the protocol implementation.

No client secret is required. The signed-in user still needs the relevant Defender role and
device-group access, so the API does not expand the user's administrative reach.

## Inventory pagination

The Defender list-machines API supports OData `$top` and `$skip`, with a maximum documented
page size of 10,000. The implementation accepts an `@odata.nextLink` when supplied and falls
back to incrementing `$skip`. This avoids the common failure mode where only the first page
of a large enterprise inventory is considered.

## Name resolution

Input may contain FQDNs or short hostnames:

- FQDN input requires an exact case-insensitive match.
- Short input matches the first DNS label.
- `DomainSuffix` restricts matches to the named DNS suffix.
- Multiple remaining records are treated as unsafe by default.
- `SelectNewestMatch` is an explicit escape hatch for environments that retain reimaged or
  duplicated device records.

## Rate limiting and retries

The tagging API is a per-machine operation. The tool therefore spaces live write attempts
and retries HTTP 408, 429, 500, 502, 503, and 504 responses. A server-provided `Retry-After`
value takes precedence; otherwise bounded exponential backoff with jitter is used.

Failures are recorded per device and do not discard the results of the remaining plan.

## Deliberate exclusions

- No unattended client-secret authentication in the example implementation
- No embedded tenant ID, client ID, access token, domain, or device identifier
- No automatic resolution of ambiguous matches
- No parallel tag writes that could unexpectedly exceed API limits
- No destructive repository or tenant-management operations
