# R-TrustTunnel local h3 compatibility patch

Upstream: h3 0.0.8, MIT, source commit
`22c1aa3f44d1463cd7644c8f654fffc9a6da305c`.
Original crates.io archive SHA-256:
`10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be`.
Upstream LICENSE is retained. The root workspace pins this copy through
`[patch.crates-io]`; it affects the TrustTunnel HTTP/3 transport and the
Hysteria 2 authentication request.

Only `src/client/stream.rs` (`RequestStream::recv_response`) changes. RFC 9114
section 4.1 makes a request stream that ends before response HEADERS a
connection error (H3_FRAME_UNEXPECTED). TrustTunnel endpoint 1.1.0 answers
`_check` and failed CONNECTs with `send_response(eof)` and drops the stream at
once; when the QUIC stream is blocked, the response is queued and the drop
then finishes the stream without it. Upstream h3 closed the whole connection,
so one lost health-check response broke every tunnelled flow. On the Android
emulator this failed 5 of 10 network acceptance runs; a Linux netem reproduction
(10 ms ±5 ms delay, 25 % reordering, 1 % loss) broke 2 of 100 downloads.

The patch returns a stream error with the same code and reason for that one
request; the stream is already finished and the connection stays open. All
other frame-sequence, framing and QUIC errors keep their upstream handling.
The client treats such a lost `_check` as healthy only after an earlier check
of the same connection returned 200 (`crates/engine/src/h3transport.rs`).

Covered by `crates/engine/tests/h3_transport.rs`
(`lost_response_fails_only_its_stream`). Do not remove this patch when
upgrading h3 while endpoint 1.1.0 is supported; re-run that test and the
Android network acceptance.
