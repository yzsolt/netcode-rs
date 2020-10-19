# netcode-rs

Pure Rust implementation of the [`netcode.io`](https://github.com/networkprotocol/netcode) protocol.

Standard version **1.02** is supported.

**Note:** `netcode-rs` is **not** production ready yet. There are [outstanding issues](https://github.com/yzsolt/netcode-rs/issues) and insufficient test coverage which currently blocks publication on [`crates.io`](https://crates.io/). Contributions are welcome, of course!

# Original implementation

`netcode-rs` is built on top of the work of these awesome people:

* [Val Vanders](https://github.com/vvanders): original Rust implementation
* [Walter Pearce](https://github.com/jaynus): forked and updated Rust implementation

# Motivation

There are several problems with the currently published [`netcode`](https://crates.io/crates/netcode) crate:
 - It uses [`libsodium`](https://github.com/jedisct1/libsodium) for encryption, which is a C dependency. There are multiple pure Rust AEAD implementations which can be used instead.
 - It's not maintained anymore, thus it only supports protocol version 1.01 and lacks important fixes which were implemented in the reference C implementation in the meantime.

`netcode-rs` aims to provide an up-to-date, pure Rust implementation which solves these issues.
