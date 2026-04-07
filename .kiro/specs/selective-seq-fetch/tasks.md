# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Response Budget Crowds Out Needed Retransmits
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists
  - **Scoped PBT Approach**: Populate a relay channel with 20 slots (seq 1-20), then issue a TXT query. Assert that ALL 20 sequence IDs are retrievable by the client (via manifest+fetch or equivalent). On unfixed code, only ~7 highest-sequence envelopes are returned per poll, so lower-sequence retransmits are unreachable.
  - **Test location**: `src/relay_handler.rs` unit test or new test in `crates/dns-socks-proxy/tests/`
  - **Setup**: Create a `RelayStore`, write 20 slots to channel "inbox" from sender "server1" (seq 1-20). Build a TXT query for that channel. Call `handle_relay_query`. Parse the response and collect returned sequence IDs.
  - **Bug Condition from design**: `isBugCondition(input)` — channel has more non-expired slots than fit in one DNS response (~7 records at 1232-byte EDNS0 budget), and the client needs lower-sequence packets that are crowded out by higher-sequence ones
  - **Expected Behavior from design**: Client can discover ALL available sequence IDs via manifest and selectively fetch only needed ones. Assert that after manifest+fetch, all 20 sequences are retrievable.
  - **On UNFIXED code**: The legacy `handle_relay_receive` returns only ~7 highest-sequence envelopes. No manifest or fetch mode exists. Test FAILS because lower-sequence packets are inaccessible.
  - **Counterexample to document**: "Legacy TXT query for channel with 20 slots returns only seq 14-20. Seq 1-13 are unreachable. Client needing seq 5 (a retransmit) cannot retrieve it."
  - Run test on UNFIXED code
  - **EXPECTED OUTCOME**: Test FAILS (this is correct - it proves the bug exists)
  - Document counterexamples found to understand root cause
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.3_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Legacy Query and Send/Status Path Backward Compatibility
  - **IMPORTANT**: Follow observation-first methodology
  - **Test location**: `src/relay_handler.rs` unit tests (or alongside existing tests)
  - **Observe on UNFIXED code**:
    - Legacy TXT query (unprefixed nonce) with 3 slots returns all 3 envelopes (fits in budget)
    - A query send path writes to store and returns ACK IP `1.2.3.4`
    - Status query returns slot count encoded as `128.x.x.x` IP
    - Empty channel TXT query returns NoError with zero answers
    - All response records have TTL 0 and AA flag set
  - **Property-based test**: Generate random channel states (1-6 slots, varying sender IDs, payload sizes 1-100 bytes) with unprefixed nonces. Assert that `handle_relay_query` returns the same envelope set as the current implementation: all non-expired slots sorted by sequence descending, budget-limited, with correct envelope format (`sender_id|seq|timestamp|base32_payload`).
  - **Additional preservation properties**:
    - For all A queries with valid send structure, response IP is ACK (`1.2.3.4`)
    - For all status queries, response IP encodes `slot_count` correctly
    - For all TXT queries on empty channels, response has zero answers and NoError rcode
    - For all responses, every record has TTL 0 and the response has AA flag
  - Verify tests pass on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

- [x] 3. Implement selective sequence fetch

  - [x] 3.1 Add `read_sequences` method to `RelayStore`
    - **File**: `src/relay_store.rs`
    - Add `pub fn read_sequences(&self, channel: &str, sequences: &[u64]) -> Vec<PacketSlot>` method
    - Iterate all sender ring buffers for the channel, collect non-expired slots whose sequence is in the requested set
    - Return owned `PacketSlot`s, same pattern as existing `read` method
    - _Bug_Condition: isBugCondition(input) where channel has more slots than fit in response budget_
    - _Expected_Behavior: Client can fetch specific sequences by ID_
    - _Preservation: Existing read/read_and_advance/ack_sequences methods unchanged_
    - _Requirements: 2.2, 2.3_

  - [x] 3.2 Add manifest and fetch modes to `handle_relay_receive`
    - **File**: `src/relay_handler.rs`
    - **Nonce prefix detection**: After extracting the nonce label, check if it starts with `m` (manifest) or `f` (fetch). If neither, fall through to existing legacy behavior unchanged.
    - **Manifest mode (`m` prefix)**:
      - Read all non-expired slots via `store.read_and_advance(channel, None)`
      - For each slot, format `seq_id,payload_len` as a compact entry
      - Pack entries as comma-separated values into TXT records (up to 255 chars per TXT record string, multiple records if needed, respecting EDNS0 budget)
      - Return TXT records with the manifest data
    - **Fetch mode (`f` prefix)**:
      - Parse sequence IDs from the DNS query name label after the nonce: `f<nonce>.<seq1>-<seq2>-<seq3>.<channel>.<domain>`
      - The label immediately after the nonce contains dash-separated decimal sequence IDs
      - Call `store.read_sequences(channel, &seq_ids)`
      - Return full envelopes for only those slots using existing `encode_envelope_parts` format and budget logic
    - **Legacy mode (no prefix)**: No changes — existing code runs as-is
    - _Bug_Condition: isBugCondition(input) where slots > response_capacity and client has already-seen sequences_
    - _Expected_Behavior: Manifest returns all seq IDs compactly; fetch returns only requested envelopes_
    - _Preservation: Legacy TXT queries (unprefixed nonce) produce identical responses_
    - _Requirements: 2.1, 2.2, 2.3, 3.4_

  - [x] 3.3 Add manifest and fetch query methods to `DnsTransport`
    - **File**: `crates/dns-socks-proxy/src/transport.rs`
    - Add `build_manifest_query_name(&self, channel) -> Result<Name>`: builds `m<nonce>.<channel>.<domain>`
    - Add `build_fetch_query_name(&self, channel, &[u64]) -> Result<Name>`: builds `f<nonce>.<seq1>-<seq2>-<seq3>.<channel>.<domain>` (dash-separated decimal IDs in one label, fits 63-char limit for 3-4 IDs)
    - Add `pub async fn recv_manifest(&self, channel) -> Result<Vec<(u64, usize)>>`: sends manifest TXT query, parses comma-separated `seq_id,payload_len` entries from TXT records
    - Add `pub async fn recv_fetch(&self, channel, &[u64]) -> Result<(Vec<Vec<u8>>, Option<u64>)>`: sends fetch TXT query for specific sequence IDs, decodes envelope responses
    - _Requirements: 2.1, 2.2_

  - [x] 3.4 Update `DedupRecvTransport` to use two-phase manifest+fetch
    - **File**: `crates/dns-socks-proxy/src/relay_transport.rs`
    - **Change `last_seen` type**: From `HashMap<String, u64>` to `HashMap<String, HashSet<u64>>` to track individual seen sequence IDs instead of just max_seq
    - **Replace `recv_frames` logic**: Instead of calling `inner.recv_frames()` directly:
      1. Call `inner.recv_manifest(channel)` to get available `(seq_id, payload_len)` pairs
      2. Filter out already-seen sequences using `last_seen` HashSet
      3. If new sequences exist, call `inner.recv_fetch(channel, &needed_ids)` for only the needed IDs
      4. If all sequences already seen, skip fetch (saves a round-trip per requirement 2.4)
      5. Add fetched sequence IDs to `last_seen` HashSet
    - **Note**: The `inner` field type needs to support the new methods. Either:
      - Add `recv_manifest` and `recv_fetch` to `TransportBackend` trait with default impls that fall back to `recv_frames`, OR
      - Use a concrete `DnsTransport` type or a new trait for the two-phase protocol, OR
      - Keep `TransportBackend` unchanged and add the two-phase logic as methods on `DnsTransport` that `DedupRecvTransport` calls via downcast or a separate field
    - Choose the approach that minimizes changes to existing code. The simplest is adding default methods to `TransportBackend` that fall back to `recv_frames`.
    - _Bug_Condition: Client re-receives already-seen sequences, wasting response budget_
    - _Expected_Behavior: Client fetches only needed sequences; skips fetch when all are seen_
    - _Preservation: DedupRecvTransport continues to prevent duplicate delivery_
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.5_

  - [x] 3.5 Update `DnsSimTransport` in test to use two-phase protocol
    - **File**: `crates/dns-socks-proxy/tests/smoltcp_relay_repro.rs`
    - Update `DnsSimTransport::recv_frames` to use the two-phase protocol:
      1. Build manifest query (`m`-prefixed nonce), call `handle_relay_query`, parse manifest TXT response to get `(seq_id, payload_len)` pairs
      2. Determine needed sequences (all of them, since DedupRecvTransport handles dedup)
      3. Build fetch query (`f`-prefixed nonce with dash-separated seq IDs in a label), call `handle_relay_query`, parse fetch TXT response and decode envelopes
      4. Ack received sequences via `store.ack_sequences`
    - This exercises the full new wire format in the integration test
    - The `dns_sim_path_stale_slots` test should continue to pass with the updated transport
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.6 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Response Budget Crowds Out Needed Retransmits
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed — all 20 sequences are now retrievable via manifest+fetch)
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.7 Verify preservation tests still pass
    - **Property 2: Preservation** - Legacy Query and Send/Status Path Backward Compatibility
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions — legacy queries, send path, status path, empty channels all behave identically)
    - Confirm all tests still pass after fix (no regressions)

- [x] 4. Checkpoint - Ensure all tests pass
  - Run `cargo test` for the full workspace to verify no regressions
  - Verify `dns_sim_path_stale_slots` test passes (end-to-end with two-phase protocol)
  - Verify `full_relay_path_dns_sim_round_trip` test passes
  - Verify `relay_path_survives_adverse_network` proptest passes (uses RelayTransport directly, unaffected)
  - Verify all existing unit tests in `relay_handler.rs`, `relay_store.rs`, `relay_transport.rs` pass
  - Ensure all tests pass, ask the user if questions arise.
