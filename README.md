h3get — HTTP/3 (QUIC) multi-stream downloader

h3get is a blazing-fast command-line downloader that speaks HTTP/3 over QUIC and fully exploits multiplexed streams. It automatically splits a file into ranges and downloads those chunks in parallel over separate HTTP/3 streams on a single QUIC connection. The client adapts the number of streams on the fly to saturate your link, shows live progress (speed, % complete, current streams, ETA), and verifies integrity via an optional .md5 sidecar.

✨ Highlights

HTTP/3/QUIC transport using quic-go’s http3.Transport.

Parallel range downloads (each chunk = its own HTTP/3 stream).

Adaptive concurrency: grows streams every second until speed plateaus.

Min/Max stream bounds (defaults: min=16, max=1024).

Progress UI with total bytes, percent, average speed, streams:N, ETA.

Output directory support (auto-create).

Redirect-aware filename: if -o is not set, the final filename comes from the post-redirect URL.

Automatic MD5 verification: fetches <URL>.md5, parses it, and compares against the downloaded file (can be disabled).

Graceful fallback to single-stream if the server doesn’t support ranges.
