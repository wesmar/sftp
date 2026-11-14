#pragma once

#include "IExternalSessionSource.h"

#include <memory>
#include <vector>

namespace sftp {

// Singleton holding all IExternalSessionSource adapters registered at plugin
// startup. Two consumers:
//   1. FsFindFirst on [Imports]\ enumerates the adapter list to render the
//      list of source folders with detection-based suffixes.
//   2. Dispatch code in FsExecuteFile / FsRenMovFile / ImportCache refresh
//      looks up a specific adapter by sourceId.
class ImportSourceRegistry {
public:
    // Read-only access to the registered adapter list. Order matches the
    // constructor's registration order (see ImportSourceRegistry.cpp).
    const std::vector<std::unique_ptr<IExternalSessionSource>>&
    Adapters() const noexcept { return m_adapters; }

    // Lookup by SourceId(). Returns nullptr if not found.
    IExternalSessionSource* Find(const char* sourceId) const noexcept;

private:
    // Constructor registers every known adapter. Called exactly once, by the
    // Meyers singleton on first access — no separate Init() step needed.
    ImportSourceRegistry();
    ImportSourceRegistry(const ImportSourceRegistry&)            = delete;
    ImportSourceRegistry& operator=(const ImportSourceRegistry&) = delete;

    friend ImportSourceRegistry& GetImportSourceRegistry();

    std::vector<std::unique_ptr<IExternalSessionSource>> m_adapters;
};

// Meyers singleton.
ImportSourceRegistry& GetImportSourceRegistry();

}  // namespace sftp
