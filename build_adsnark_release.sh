#!/bin/bash

# Exit if any subcommand fails
set -e

cargo +nightly -Z package-features build --release --package zokrates_adsnark_cli --features="libsnark"
