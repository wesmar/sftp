#include "ImportSourceRegistry.h"
#include "FileZillaAdapter.h"
#include "KittyAdapter.h"
#include "OpenSshAdapter.h"
#include "PuttyAdapter.h"
#include "SecureCrtAdapter.h"
#include "WinScpAdapter.h"

#include <cassert>
#include <cstring>

namespace sftp {

namespace {

// Cache-section names use `.` as the split separator between fixed segments
// (`__import.<sourceId>.<channelTag>.<displayName>`), so a SourceId that
// contains a dot or a non-ASCII character silently corrupts the split on
// restart. Enforce the same character class the on-disk parser assumes.
bool IsValidSourceId(const char* id) noexcept
{
    if (!id || !id[0]) return false;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(id);
         *p; ++p)
    {
        const bool ok = (*p >= 'a' && *p <= 'z') ||
                        (*p >= '0' && *p <= '9') ||
                        (*p == '_' || *p == '-');
        if (!ok) return false;
    }
    return true;
}

void RegisterAdapter(
    std::vector<std::unique_ptr<IExternalSessionSource>>& list,
    std::unique_ptr<IExternalSessionSource> adapter)
{
    if (!adapter) return;
    if (!IsValidSourceId(adapter->SourceId())) {
        assert(false && "adapter SourceId must be lowercase ASCII, digits, "
                        "'_' or '-' — see ImportCache section-name format");
        return;  // Refuse to register; skipping is safer than cache corruption.
    }
    list.push_back(std::move(adapter));
}

}  // namespace

ImportSourceRegistry& GetImportSourceRegistry()
{
    static ImportSourceRegistry inst;
    return inst;
}

ImportSourceRegistry::ImportSourceRegistry()
{
    // Registration order is a dev detail: TC re-sorts the [Imports]\ listing
    // alphabetically by name at render time, so this order is not visible to
    // the user under normal panel-sort settings. It only surfaces if the
    // panel is switched to "no sort".
    RegisterAdapter(m_adapters, std::make_unique<SecureCrtAdapter>());
    RegisterAdapter(m_adapters, std::make_unique<PuttyAdapter>());
    RegisterAdapter(m_adapters, std::make_unique<WinScpAdapter>());
    RegisterAdapter(m_adapters, std::make_unique<FileZillaAdapter>());
    RegisterAdapter(m_adapters, std::make_unique<KittyAdapter>());
    RegisterAdapter(m_adapters, std::make_unique<OpenSshAdapter>());
}

IExternalSessionSource* ImportSourceRegistry::Find(const char* sourceId) const noexcept
{
    if (!sourceId) return nullptr;
    for (const auto& a : m_adapters) {
        if (std::strcmp(a->SourceId(), sourceId) == 0)
            return a.get();
    }
    return nullptr;
}

}  // namespace sftp
