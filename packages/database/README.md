# Database package

This package owns Himitsu's PostgreSQL schema and ordered SQL migrations. Application code must not create schema objects at runtime.

## Migration contract

- Apply files in `migrations/` by ascending number as a dedicated deployment step.
- Record successful versions in the deployment migration ledger before starting application containers.
- Never edit a migration that has shipped; add a new forward migration instead.
- The matching `*.down.sql` file is for local verification and operator-reviewed rollback only.

The root tenant records (`organizations`) and global identities (`users`) do not carry `org_id`. Every tenant-owned table does, and composite foreign keys ensure children cannot refer to resources in another organization.

## Validation

Run against a fresh, disposable PostgreSQL database:

```sh
DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/himitsu_test \
  ./packages/database/scripts/test-schema.sh
```

The test applies the migration, checks the required tables and tenant columns, exercises same-environment uniqueness and cross-tenant foreign-key rejection, inserts representative records, applies the down migration, and checks that no relations remain.
