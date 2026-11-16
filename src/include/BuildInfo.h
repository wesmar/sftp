#pragma once

// Build metadata surfaced to the user and the log so that a beta
// installation is unambiguously identifiable — the version bump in
// `version.h` happens once per release (`10.0.2.0` → `10.0.2.1`),
// but between-beta iterations only carry different git tags. Without
// these constants the beta cycle would present as "the same 10.0.2.0"
// to anyone inspecting the plugin from Total Commander.
//
// The three defines below are the *fallback*. build.ps1 writes
// `build_info_gen.h` next to this file before the compiler runs, with the
// tag, short SHA and commit date from git; the `__has_include` guard below
// picks it up - no compiler flag needed. Outside a git checkout the plugin
// labels itself `local`. `build_info_gen.h` is gitignored.

#if __has_include("build_info_gen.h")
#  include "build_info_gen.h"
#endif

#ifndef SFTP_BUILD_TAG
#define SFTP_BUILD_TAG  "local"
#endif

#ifndef SFTP_BUILD_SHA
#define SFTP_BUILD_SHA  "unknown"
#endif

// No __DATE__: a build has to depend on its sources only, never on the day
// it was made.
#ifndef SFTP_BUILD_DATE
#define SFTP_BUILD_DATE "unknown"
#endif
