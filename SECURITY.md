# Security policy

## Reporting

Please report potential security issues privately through the repository owner's GitHub
profile. Do not open a public issue containing access tokens, tenant identifiers, internal
hostnames, machine IDs, API responses, or other organizational data.

## Supported version

The latest version on the default branch is supported.

## Operational guidance

This project is an administrative example and is not a substitute for organizational change
control. Test it with synthetic data and dry-run mode before use in an authorized tenant.

Never commit:

- OAuth access or refresh tokens
- Client secrets or certificates
- Real tenant, device, user, domain, or customer identifiers
- Production API responses or result exports
- Microsoft Defender onboarding or offboarding packages
