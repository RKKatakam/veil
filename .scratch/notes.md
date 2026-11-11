# rv-access review notes (base fd94a07f)

Area: who can see and change what on the server (crates/veil-server).
Tests: crates/veil-server/tests/server_hub/rv_access.rs (all `#[ignore = "BUG-…"]`).
Run: `bash ~/.cache/veil-orch/server-tests.sh rv_access:: --ignored --test-threads=3`
Last run (.scratch/t3.log): 9 tests, 9 fail, each for the reason its row claims.

## Confirmed and filed (docs/BUGS.md, last section)
- 1850 ci.rs readable_footprint: check results shown to readers of less than the poster's view (2 tests).
- 1851 embargo.rs prepare_push step 1: release / new deadline by a push of a record naming the pusher's own group.
- 1852 ci.rs post_check_route: any participant's results revert a landed change (and move main@tested).
- 1853 api.rs get_rings / get_ring: every ring to every participant; scope = unkeyed hash of the line's path.
- 1855 changes + land: follow-up on an embargoed base landed on an ordinary branch publishes the embargoed change.
- 1856 no route or command adds an admin (VISIBILITY.md promises it).
- 1857 embargo.rs release_due: `?` in the loop; one conflicted release blocks every later one, all projects.
- 1858 sync.rs push: a fast-forward to a snapshot the server holds is not checked for write access.

## Not filed (noted under the table in BUGS.md)
- A group manager's right cannot be taken away (missing feature; VISIBILITY.md does not promise it). 1854 unused.
- change_group: 404 vs 403 tells whether a group name exists.
- An event stream outlives its device's removal by its person.
- checks_for dedupes by name before the visibility filter.

## Checked, sound (by reading)
- perm::open / epochs / session cache; triggers of 0006 cover members, admins, sessions, devices, bars, projects, groups.
- Agent session minting (never past its parent, person_only); not_runner on objects, push, land, changes,
  embargo release and every PR write.
- query resolve_real (embargo withheld for everyone on q/), Ask::file_path.
- events: every emit reopens the subscriber's view; check.requested and reverted are filtered.
- bisect status_route projection; landing::seen; shares list/put/remove.
- grant check (device, epochs), ranged reads prepay; prs class visibility and narrowing.
- hidden_for_embargo filters on every branch read; only admins delete a branch; force is admins'.

## Not reached
- sync.rs fetch internals, landing agent_stack internals, search scoring, derive/*, cache/* (S9), daemon (S6).
