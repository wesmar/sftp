#pragma once

#include <windows.h>

// A file that fails in a multi-file download can be skipped - this once or
// for the rest of the batch - instead of ending the whole operation. The
// choice belongs to the transfer thread and ends with the operation.
namespace download_batch {

// Start and end of a multi-file download on this thread (FsStatusInfo).
void Begin() noexcept;
void End() noexcept;

// What FsGetFile reports for a file that could not be downloaded: the read
// error itself, a user abort, or FS_FILE_OK for a skipped file, whose partial
// local copy is removed first. Only a copy inside a batch is offered the
// choice: after a move Total Commander would delete the source of a file
// that never arrived, and a resumed download keeps its part for next time.
int ResolveReadError(LPCWSTR remoteName, LPCWSTR localName, bool move, bool resume);

} // namespace download_batch
