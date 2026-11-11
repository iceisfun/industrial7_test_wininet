# urlcache_enum_groups evidence

## Triage 2026-11-11 (Win10 22H2 19041.2788 VM, tri-urlcache_enum_groups-*)

Baseline: 20 tests failed, 25 skipped, 68 FAIL lines. Root causes:

1. SetUrlCacheEntryGroup(ADD) on a fresh group (default 0 KB disk quota) returns FALSE with ERROR_NOT_ENOUGH_QUOTA (1816)
   for any non-empty entry, but the membership and the group's dwDiskUsage ARE updated. Probed with quotas 0/1/4/1000/0x7fffffff/0xffffffff:
   only quota 0 fails (quota 1 KB with a 5-byte entry succeeds). Cause: wrong-expectation. Change: new `SEGQ()` helper (ueg.h)
   treats 1816 as "added" at ADD call sites in groups.c, extra.c, enum_ex.c (the follow-up enumeration checks still verify membership);
   the two `EXPECT_ERR(0)` in ueg_seg_add_remove_membership accept 0 or 1816. Fixes ueg_seg_*, ueg_delete_group_*, sticky tests,
   ueg_group_usage_tracks_members, ueg_x_header_*, ueg_filter_matrix_*, and the ~25 SKIPs ("group setup failed (1816)", XGROUP_OR_SKIP helper) .
2. CreateUrlCacheGroup(GIDONLY|NONPURGEABLE) (flags 5 and 7) fails with ERROR_INVALID_PARAMETER (87). Cause: wrong-expectation.
   Change: ueg_create_group_valid_flags and ueg_create_group_gidonly_creates_nothing expect 0/87 for these combinations.
3. ueg_x_delete_ahead_not_returned: a group-scoped FindNextUrlCacheEntryExA still returns an entry deleted ahead of the cursor
   (snapshot). Cause: wrong-expectation. Change: expect all 4 entries once.
