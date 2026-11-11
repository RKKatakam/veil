# rv-access review notes (base fd94a07f)

Area: who can see and change what on the server (crates/veil-server).
Tests: crates/veil-server/tests/server_hub/rv_access.rs. Bug numbers BUG-1850..1859.

## Candidates
- 1850 ci.rs readable_footprint: (a) admin whole view -> admin_only decided from root entries only
  (entry counts as covered if any rule at or below it); (b) un-narrowed session + [checks.<name>] paths
  -> footprint = configured paths, not the session's view.
- 1851 embargo.rs prepare_push step 1 authorises against the pushed record's groups; standalone record
  updates until_ms / releases (sync.rs:3155) an existing embargo.
- 1852 ci.rs post_check_route: any participant's results drive bisect/revert (and main@tested).
- 1853 api.rs get_rings/get_ring: all rings to every participant; scope = unkeyed hash of rule path.
- 1854 no route to remove a group manager.
- 1855 embargo: follow-up landed on an ordinary branch via /changes + /land is not hidden. (to confirm)
- 1856 no route to add an admin.
- 1857 embargo.rs release_due: `?` in the loop; one failing release blocks all later ones, all projects.

## Checked, sound (by reading)
- perm::open / epochs / session cache; agent session minting (never past parent, person_only).
- not_runner on objects, push, land, changes, embargo release, every PR write.
- query resolve_real (embargo withheld for everyone on q/), Ask::file_path.
- events: every emit re-opens the subscriber's view; check.requested / reverted filtered.
- bisect status_route projection; landing::seen.
- shares list/put/remove; grant check (device, epochs), ranged reads prepay.
- prs class visibility; narrowed PR handling.

## Not reached
- sync.rs fetch internals, landing/service.rs agent_stack internals, search scoring, derive/*, cache/* (S9), daemon.
