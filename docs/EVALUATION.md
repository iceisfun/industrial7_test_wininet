# State evaluation (2026-11-10)

Written after lanea's ultracode workflow (wf_56dfc93b-287) was suspended when its token budget ran out. Evaluated by Sonnet 5.5 agents, read-only, from source, EVIDENCE.md, the journal and the git log. Nothing was relaunched.

Correction to the synthesis below: `origin/workflow` and `origin/master` were already the same commit (cd25305) when this was done, so master already holds the as-is snapshot. The `workflow` branch is deleted because it carried nothing extra. All 21 areas were cross-compiled with mingw at that commit (all build). No Win10 run was done, so every "passes on Win10" figure is the earlier agents' claim, not re-verified. Where the text says to decide before deleting or pushing, that was done at the user's explicit request.

Evaluated by Sonnet 5.5, read-only. Repo: `/data/i7wt/wininet-eval/repo`. Nothing was relaunched, deleted or pushed.

## Caveats
- No Win10 VM was available. Every "passed on Win10" figure below is a claim from the journal, EVIDENCE.md or a commit message. I could not re-verify any of them.
- `python3 tools/coverage.py .` did not finish within 120 s, so it is not cheap. `COVERAGE.md` and `HANDOFF.md` do not exist. `tools/public_surface.txt` was never produced, because the Surface phase never ran.
- The per-area reviews were spot-checked against the repo (TEST counts, EVIDENCE.md presence, phase structure). I did not re-derive their finer claims.

## State of the repo
- The branch `workflow` is a single "as-is snapshot" commit (`cd25305`) on top of about 124 agent commits. It adds `workflows/` (script, journals, RESUME.md). Master on GitHub was not updated.
- It has 21 test areas under `tests/`. 19 have an EVIDENCE.md. `core_smoke`, `net_loopback`, `time_and_misc_helpers` and `urlcache_enum_groups` do not, and `http_edge_protocol` has one that was only filled in at the snapshot.
- All areas are reported to build. The shared infrastructure (common/ loopback HTTP, HTTPS and FTP server library, `tools/vm_run.sh`, `vm_matrix.sh`) exists.
- `results/win10/` holds only `core_smoke.txt` and `net_loopback.txt`. Every other pass transcript was gitignored or kept outside the repo, so no pass can be audited from the repo itself.
- `tools/` has the export lists, `coverage.py` and `suggest_areas.py`.
- The snapshot commit also changed source files without any journal or VM record. It changed code in async_callbacks, https_tls, options_table, cookies and others, and it added about 15 new test files (e.g. `ck_rev.c`, `rs_extra.c`, `more.c`, `rsp_more.c`, `sh_rv.c`, `tls_combined.c`, `ot_live.c`, `ot_conns_child.c`).

## Per-area table
TEST counts are `^TEST(` greps of the source files. They can differ from the counts the VM runs reported.

| Area | Tests (src) | Evidence | Verdict | Key gap |
|---|---|---|---|---|
| core_smoke | 3 | none (committed result) | complete | trivial scaffold |
| net_loopback | 26 | committed result, 132 checks | usable | no EVIDENCE.md; a 3500 ms stop-time assert is flaky-prone |
| url_crack | 592 | claim: 915 tests / 54695 checks (pass 2) | usable-with-gaps | `review3.c` and 7ef8fdf are unrun; its header claims VM evidence that EVIDENCE.md lacks |
| options_table | 92 (plus a ~3300-line generated table) | claim: 128/128 | usable-with-gaps | `ot_conns_child.c`, `ot_live.c` and the other edits (15 tests) are unrun; EVIDENCE.md tags guesses as `[D][VM]` |
| session_handles | 222 | claim: 202/202 | usable-with-gaps | `sh_rv.c` (20 tests) unrun; EVIDENCE.md says "every hard CHECK passed", which is stale |
| proxy_connectivity | 239 | claim: 239/239 (boot 6) | usable-with-gaps | boot 7 has no recorded counts; it sets option 39/95, which has cross-process side effects; it assumes a lab VM with no DNS |
| http_request_wire | 303 | boots 1, 2, C1-C3 only | usable-with-gaps | no PASS ever recorded; the c9d400e child-process split and TLS retry are unrun |
| http_response_headers | 190 | claim: 173 tests / 42879 checks | usable-with-gaps | `rsp_more.c` (about 17 tests) unrun and absent from EVIDENCE.md |
| http_edge_protocol | 2 greps (a macro hides the real count) | none recorded | incomplete | never shown to pass; the 2c3200a timeout change touches shared server setup; its EVIDENCE.md findings were written at suspension |
| http_body_io | 347 | claim: 508 tests, 1 failed (boot 4) | usable-with-gaps | no zero-failure boot; the a4ffd43 HTTPS retry is unrun |
| http_redirect_status | 268 | claim: 319 tests (rs4) | usable-with-gaps | `rs_extra.c` (about 39 tests) unrun; sleep-based request-count races |
| http_auth | 237 | claim: 218 tests, 0 failed | usable-with-gaps | `more.c` (19 tests) and the `https_cb.c` edit are unrun |
| cookies | 359 | claim: 326 tests | usable-with-gaps | `ck_rev.c` (33 tests) is decomp-only and has never been run |
| urlcache_entries | 304 | claim: 282 tests (uce7) | usable-with-gaps | `uce_review.c` (22 tests) and the 8060d30 edits are unrun |
| urlcache_enum_groups | 183 | none | unverified | never run on Win10; some tests delete cache entries or containers, and their scoping is unconfirmed |
| time_and_misc_helpers | 164 | none | unverified | never run anywhere; `cache_api_helpers.c` was never reviewed |
| http_cache_integration | 250 | claim: 250 tests, 1 failed | usable-with-gaps | no clean boot; the final row of the table is a placeholder |
| https_tls | 203 | claim: 187 tests (tls7) | usable-with-gaps | `tls_combined.c` and other edits (about 16 tests) are unrun; its header claim of VM validation is false; 12030 failures are hidden behind a retry |
| async_callbacks | 243 | claim: 217 tests (ac6) | usable-with-gaps | the 26 `ac_y_*` tests are unrun; some expectations are guesses |
| ftp_client | 289 | claim: 12 failures at run 1 | incomplete | no passing boot; EVIDENCE.md falsely says all passed; 80 or more tests never ran |
| gopher_and_stubs | 195 | claim: gsb5 195/195 | usable-with-gaps | the final fix postdates the pass claim; no journal corroboration |

Pattern across areas: each had one or more Win10-validated boots, and then a later "review pass" (a separate adversarial-reviewer agent) added tests that had no VM run. These tests carry decomp-derived expectations that are labelled as facts. They are a larger risk than the validated cores.

## What the suspended workflow still owed
- The script has phases Research, Foundation, then a per-area Write, Review and Win10 pipeline, then Surface, Coverage, Gapfill and Final.
- Research and Foundation are done.
- The per-area pipeline is mostly done, but every Review agent is a "started" line only in the journal, with no result. Many areas have no write result either.
- Never run:
  - **Surface:** `tools/public_surface.txt` (the documented public API list) was not produced.
  - **Coverage:** no measurement of uncovered exports. The repo has 299 wininet exports in `tools/wininet_exports.txt`.
  - **Gapfill:** the `gap_NN` areas for exports that are uncovered.
  - **Final:** `make clean && make` for all areas, a full Win10 pass under `results/win10-full/`, a safety audit, README, COVERAGE.md and HANDOFF.md, and the push to master. README.md exists but is not the Final deliverable.

## What is safe to rely on
- The infrastructure: the loopback server library, the VM runner and the shared test harness. `net_loopback` has a committed result (26 tests, 132 checks). `core_smoke` is trivial.
- The validated cores, as claims from the journal and EVIDENCE.md: url_crack pass 2, options_table 128 tests, session_handles 202, proxy_connectivity 239, http_response_headers 173, http_auth 218, urlcache_entries 282, https_tls 187, async_callbacks 217, cookies 326. The numbers hold for Win10 build 19041.2193 only.
- Safety: the review found no internet use (all hosts are loopback or fake). Cache deletions are scoped by design, except the two flagged in urlcache_enum_groups.
- Not safe to rely on: the post-VM review-pass files listed above, `ftp_client`, `http_edge_protocol` and the two never-run areas. Expectations that cite `[D]` (decomp) or `[VM]` without a boot ID are unverified.

## Ranked next steps (cost in agent and VM effort)
1. **Triage the repo into a master-ready state (low, about 1-2 hours, no VM).**
   - Fix the false statements: the `review3.c` header, the `tls_combined.c:17` comment, the "every hard CHECK passed" lines in session_handles and ftp_client, and the `[D][VM]` tags in options_table.
   - Add the missing EVIDENCE.md notes and a status page.
   - Decide whether to merge only the committed pre-snapshot state.
2. **Build every area and run each on a Win10 VM once at tip (medium; VM time is the main cost).** About 21 exes, with long runs (up to about 450 s each). This single pass resolves most unknowns. Triage failures by hand, or with Sonnet on a few areas at a time. Commit `results/win10/*.txt` for each exe.
3. **Triage the unrun review-pass files (medium).** The order is `ck_rev.c`, `rs_extra.c`, `more.c`, `rsp_more.c`, `sh_rv.c`, `tls_combined.c`, `ac_y.c`, `ot_*`, `uce_review.c`. Where the VM contradicts an expectation, fix it or downgrade the check to a note.
4. **Finish the never-passed areas (medium to high):** `ftp_client`, `http_edge_protocol`, `urlcache_enum_groups`, `time_and_misc_helpers`. Review the destructive loops in `urlcache_enum_groups` first (delete entries and containers, scoping unconfirmed).
5. **Fix harness issues (low):** the double evaluation of `EXPECT_EQ` in `common/t.h`; the root cause of the transient 12030/12031 on first HTTPS requests, instead of the retry macros; and the 3500 ms stop-time assert.
6. **Surface, Coverage and Gapfill (high):** these have not started. Run them with Sonnet, in a reduced form.
7. **Final integrator (medium):** docs and the push. Do it only after step 2.

## Recommendation
- Do not relaunch the original script as-is. It would re-run about 21 areas with Opus writer, reviewer and VM agents, and its paths and models are tied to lanea's host.
- Resume manually with a small, trimmed script or by hand, in this order: steps 1, 2 and 3, then 4. Use Sonnet for triage, keep Opus out, and run only one agent per area against an existing pass. Delay Surface, Coverage and Gapfill until a full Win10 pass exists.
- To get master in a usable state quickly, merge the infrastructure plus the areas whose validated cores have run (see the list above), flag the unrun files in the commit message, and leave the four unfinished areas on the branch.
- Per your request, delete the `workflow` branch and push to master only after this evaluation is accepted. This run did neither.
- Keep `workflows/RESUME.md` and the journals, for example under `docs/`, because they are the only record of what each agent returned.


## Win10 run at tip (added after the evaluation above)

The evaluation above was written before a VM was available. The corpus was then run on local Win10 22H2 guests (base `bb depot get m2`, ntdll 10.0.19041.2788, UBR 2965; `win10vm.sh` from industrial7 with `tools/vm_run_local.sh`, one boot per area, 7 in parallel). Transcripts are in `results/win10/`.

Result: 8 of 21 areas PASS, 13 FAIL (an earlier version of this doc said 7 and 14: a miscount), none crashed or timed out. Failures are not triaged: each is either a wrong expectation (the unrun post-VM review files predicted in the evaluation) or a real harness issue (several involve HTTPS, e.g. `rsp_life_https_response_headers`, `ck_wire_https_secure_cookie_sent`, `netlb_https_tls12_only_server`).

| area | result | tests | failed tests | failed checks |
|---|---|---|---|---|
| async_callbacks | FAIL | 243 | 1 | 2 |
| cookies | FAIL | 359 | 1 | 4 |
| core_smoke | PASS | 3 | 0 | 0 |
| ftp_client | FAIL | 289 | 6 | 11 |
| gopher_and_stubs | PASS | 195 | 0 | 0 |
| http_auth | FAIL | 237 | 2 | 4 |
| http_body_io | PASS | 508 | 0 | 0 |
| http_cache_integration | PASS | 250 | 0 | 0 |
| http_edge_protocol | PASS | 350 | 0 | 0 |
| http_redirect_status | FAIL | 358 | 2 | 2 |
| http_request_wire | PASS | 362 | 0 | 0 |
| http_response_headers | FAIL | 190 | 2 | 7 |
| https_tls | PASS | 203 | 0 | 0 |
| net_loopback | FAIL | 26 | 1 | 1 |
| options_table | FAIL | 143 | 4 | 5 |
| proxy_connectivity | FAIL | 239 | 1 | 1 |
| session_handles | FAIL | 222 | 1 | 1 |
| time_and_misc_helpers | FAIL | 164 | 4 | 5 |
| url_crack | PASS | 934 | 0 | 0 |
| urlcache_entries | FAIL | 304 | 1 | 2 |
| urlcache_enum_groups | FAIL | 183 | 20 | 48 |

Note `urlcache_enum_groups` (20 failed, 25 skipped) has never passed and is the largest gap; the others are 1-6 failures each. `https_tls`, `http_request_wire`, `http_edge_protocol`, `http_body_io` and `http_cache_integration` pass completely at tip.

## After triage (2026-11-11)

13 Sonnet 5.5 triage agents each fixed one failing area on the local Win10 VM (branches `triage/<area>`, merged here). Causes found: wrong expectations vs Win10 (most), real test bugs (ftp_client: `S_SEND` on a pointer sent 7 bytes, async completion count read from the wrong field), and timing/environment variation. Then the merged tree was run twice on the VM, full corpus, one boot per area:

- run 1: 21 of 21 PASS.
- run 2: 18 PASS, 3 FAIL (flakes): `async_callbacks` (the optional-trailing-40,41 acceptance added by triage trims 4 characters instead of 6, so it never accepts the shorter sequence), `session_handles` `sh_conc_create_children_while_session_closed` (off-by-one in close accounting), `proxy_connectivity` `pc_wire2_connect_https_scheme_proxy_entry_uppercase`-adjacent reuse test (first HTTPS request fails).

Open and unexplained: the first HTTPS request over the loopback schannel server intermittently fails with 12030 (ERROR_INTERNET_CONNECTION_ABORTED). It showed in cookies, http_response_headers, net_loopback and proxy_connectivity. Triage added per-test retry or downgraded to notes; the root cause (server `srv_tls.c` vs client) is not identified. Treat `https_tls`-dependent areas as flaky until it is.
