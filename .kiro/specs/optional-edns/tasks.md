# Implementation Plan: Optional EDNS0

## Overview

Thread a `--no-edns` boolean from CLI through config into `DnsTransport` and `recv_frames_parallel`, conditionally omitting the EDNS0 OPT record on TXT queries. Four config structs get a new field, `DnsTransport` gets a `use_edns` field + builder, `build_dns_query` gains a `use_edns` parameter, and the two binaries wire it through at transport construction time.

## Tasks

- [x] 1. Add `no_edns` to CLI and config structs
  - [x] 1.1 Add `no_edns: bool` field to `SocksClientCli` with `#[arg(long)]` and wire it into `SocksClientCli::into_config()` → `SocksClientConfig`
    - Add `pub no_edns: bool` to both `SocksClientCli` and `SocksClientConfig`
    - Set `no_edns: self.no_edns` in `into_config()`
    - _Requirements: 1.1, 1.2, 1.3_
  - [x] 1.2 Add `no_edns: bool` field to `ExitNodeCli` with `#[arg(long)]` and wire it into `ExitNodeCli::into_config()` → `ExitNodeConfig`
    - Add `pub no_edns: bool` to both `ExitNodeCli` and `ExitNodeConfig`
    - Set `no_edns: self.no_edns` in `into_config()`
    - _Requirements: 2.1, 2.2, 2.3_
  - [x] 1.3 Update `base_socks_cli()` and `base_exit_cli()` test helpers in `config.rs` to include `no_edns: false`
    - _Requirements: 1.2, 2.2_

- [x] 2. Add `use_edns` to `DnsTransport` and update query building
  - [x] 2.1 Add `use_edns: bool` field (default `true`) to `DnsTransport` and a `with_edns(bool)` builder method
    - Initialize `use_edns: true` in `DnsTransport::new()`
    - Add `pub fn with_edns(mut self, use_edns: bool) -> Self`
    - _Requirements: 3.1, 3.4_
  - [x] 2.2 Change `build_dns_query` signature to accept `use_edns: bool` and conditionally add OPT record only when `record_type == TXT && use_edns`
    - Update the existing `if record_type == RecordType::TXT` guard to `if record_type == RecordType::TXT && use_edns`
    - Update all internal call sites (`send_frame`, `recv_frames`, `query_status`) to pass `self.use_edns`
    - _Requirements: 3.2, 3.3, 4.1, 4.2_
  - [x] 2.3 Add `use_edns: bool` parameter to `recv_frames_parallel` and `recv_single_parallel_query`, pass it through to `DnsTransport::build_dns_query`
    - _Requirements: 5.1, 5.2, 5.3_
  - [x] 2.4 Write property test for `build_dns_query` EDNS0 behavior
    - **Property 1: EDNS0 OPT record presence is determined by record type and use_edns flag**
    - **Validates: Requirements 3.2, 3.3, 4.1, 4.2**

- [x] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Wire EDNS0 flag through binary entry points
  - [x] 4.1 In `socks_client.rs`, add `.with_edns(!config.no_edns)` to both the per-session `DnsTransport` and the control-channel poller `DnsTransport`
    - _Requirements: 6.1, 6.3_
  - [x] 4.2 In `exit_node.rs`, add `.with_edns(!config.no_edns)` to the standalone-mode `DnsTransport` construction, and pass `!config.no_edns` to the `recv_frames_parallel` call site
    - _Requirements: 6.2, 5.1_

- [x] 5. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- DirectTransport is unaffected (bypasses DNS entirely) — no task needed
- The `no_edns` → `use_edns` inversion keeps CLI negative-sense (`--no-edns` disables) while transport is positive-sense (`use_edns = true` means include OPT)
