**Every HTTP write now reaches the federation peers, or says it did not.**
On PostgreSQL, `PUT` and `DELETE /api/v1/memories/{id}`, `POST
/api/v1/links`, archive and restore committed locally and never sent the
change to the peers (#9087, #9005, #9052). On both backends `POST
/api/v1/forget` never sent the erasure (#9023). All of them now go through
one fan-out funnel before the response: the success receipt carries the
real `quorum_acks` / `quorum_n` / `quorum_required`, and a quorum miss is
the existing `202` with `quorum_met: false` (`durability: "local"`),
never a silent success. A bulk forget sends one deletion tombstone per
erased id.

`POST /api/v1/consolidate` with tombstoned sources no longer fails
finalize with `CONSOLIDATE_TOMBSTONE_MISSING` and then fans out hard
deletions of the sources (#9057). Finalize reads each source back and
requires its tombstone; if it cannot, the reply is the id-bearing `202`
naming the exact code and the peers receive nothing.

The same funnel now carries the governance, roster and import writes. On
PostgreSQL, `POST /api/v1/agents`, setting or clearing a namespace
standard, and approving or rejecting a pending action (governance route
and the K10 `POST /api/v1/approvals/{pending_id}` route) committed locally
and sent nothing to the peers (#9152). On both backends `POST
/api/v1/capture_turn`, `POST /api/v1/entities` and `POST /api/v1/import`
(rows and links) never fanned out (#9153). Each now delivers the same
effect the SQLite governance arm always sent (`memories`,
`pending_decisions`, `namespace_meta`, `namespace_meta_clears`, `links`),
with the quorum fields on success or the `202 quorum_met: false` reply.
The SQLite `register_agent` and every `fanout_or_pending` caller no longer
turn a broadcast error into a plain success.
