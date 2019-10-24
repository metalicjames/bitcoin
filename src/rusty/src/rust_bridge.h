// Rust functions which are exposed to C++ (ie are #[no_mangle] pub extern "C")
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RUSTY_SRC_RUST_BRIDGE_H
#define BITCOIN_RUSTY_SRC_RUST_BRIDGE_H

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <new>

namespace rust_os_rng {

extern "C" {

uint32_t get_secure_random_uint32();

} // extern "C"

} // namespace rust_os_rng

#endif // BITCOIN_RUSTY_SRC_RUST_BRIDGE_H
