// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Emit `BUILD_GIT_SHA` and `BUILD_GIT_BRANCH` so the binary's
//! `version` subcommand can report the exact commit it was built
//! from. Lets users verify that a freshly-built `encrypted-serial`
//! actually contains a specific change rather than a stale binary.

fn main() {
    // Best-effort: in a non-git checkout (e.g. a tarball), just
    // emit empty values rather than failing the build.
    let _ = build_rs_git_info::emit_git_info();
}
