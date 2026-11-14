#pragma once

// Build metadata surfaced to the user and the log so that a beta
// installation is unambiguously identifiable — the version bump in
// `version.h` happens once per release (`10.0.2.0` → `10.0.2.1`),
// but between-beta iterations only carry different git tags. Without
// these constants the beta cycle would present as "the same 10.0.2.0"
// to anyone inspecting the plugin from Total Commander.
//
// The three defines below are the *fallback* used by a plain local
// build. The GitHub Actions release workflow overrides them by writing
// a `build_info_gen.h` next to this file **before** the compiler runs;
// the `__has_include` guard below picks it up automatically — no
// compiler flag needed. That gives every workflow-built artifact real
// values while a developer's `build.ps1` still produces a self-labelled
// `local` build without needing to touch git or CI. `build_info_gen.h`
// is gitignored so it never gets committed by mistake.

#if __has_include("build_info_gen.h")
#  include "build_info_gen.h"
#endif

#ifndef SFTP_BUILD_TAG
#define SFTP_BUILD_TAG  "local"
#endif

#ifndef SFTP_BUILD_SHA
#define SFTP_BUILD_SHA  "unknown"
#endif

#ifndef SFTP_BUILD_DATE
#define SFTP_BUILD_DATE __DATE__
#endif
