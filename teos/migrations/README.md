# Structure:
- `postgres`: Contains `.sql` migrations for postgres databases.
- `sqlite`: Contains `.sql` migrations for sqlite databases.


# Migrations Extra Documentation (`migrations/*/*.md`):

Migrations cannot be edited once applied to the database. Thus, writing/editing any comments or explanations in the `.sql` files would break the tower for users who have applied those migrations.

Any additional comments that we need to add after a migration has been applied should be in `MID_MNAME.md` instead.
