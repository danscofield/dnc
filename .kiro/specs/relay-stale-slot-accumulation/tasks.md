# Tasks — Relay Stale Slot Accumulation Bugfix

## Tasks

- [x] 1. Revert `RelayTransport.send_frame` to use `self.sender_id` directly
  - [x] 1.1 Remove `send_seq: AtomicU64` field from `RelayTransport` struct
  - [x] 1.2 Change `send_frame` to use `&self.sender_id` instead of `format!("{}-{}", self.sender_id, seq)`
  - [x] 1.3 Update `uses_own_sender_id_not_parameter` test to expect `real-sender` (no suffix)
- [x] 2. Revert `handle_relay_send` to use `sender_id` directly
  - [x] 2.1 Remove nonce-based unique sender_id in `handle_relay_send` — use `sender_id` from `decode_send_query` as-is
- [x] 3. Revert `DnsSimTransport.send_frame` in test file to use `self.sender_id` directly
  - [x] 3.1 Remove `send_seq: AtomicU64` field from `DnsSimTransport`
  - [x] 3.2 Change `send_frame` to use `&self.sender_id` instead of `format!("{}-{}", self.sender_id, seq)`
- [-] 4. Run existing tests to validate fix
  - [ ] 4.1 Run `dns_sim_path_stale_slots` — should pass (was timing out before)
  - [ ] 4.2 Run `full_relay_path_round_trip` — should continue to pass
  - [ ] 4.3 Run `full_relay_path_dns_sim_round_trip` — should continue to pass
