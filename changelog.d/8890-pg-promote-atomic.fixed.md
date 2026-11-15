**PostgreSQL vertical promote and entity register commit atomically (#8890, #4034).**
On PostgreSQL, `promote` to a namespace wrote the clone row in one
transaction and its `derived_from` edge in a second one, so a refused or
failed link left the clone behind, or left a same-title target in the
destination namespace overwritten by a merge that had no edge.
`entity_register` wrote the entity row and its alias rows the same way.
Both now run the store funnel body and the follow-up writes on ONE
transaction: either every row and link commits or none does. The lineage
cycle guard and the link existence checks read on that transaction, so
they see the uncommitted clone (before, the lineage guard skipped it).
New PostgreSQL tests pin the rollback for a failed link, a refused
lineage link and a failed alias insert, and the #4034 row locks for the
trait `update` and the `expected_version: None` write. SQLite behaviour
is unchanged.
