#include "Cleanup.hpp"
#include "Kernel.hpp"
#include "HostsBlocker.hpp"
#include "FileIntegrity.hpp"
#include "SSH.hpp"
#include "SELinux.hpp"
#include "AppArmor.hpp"

CleanupResult Cleanup::removeAllTraces() {
    CleanupResult r;
    KernelSecurity::removePersistenceConf()  ? ++r.ok : ++r.fail;
    HostsBlocker::apply(HostsBlocker::NONE)  ? ++r.ok : ++r.fail;
    FileIntegrity::purge()                   ? ++r.ok : ++r.fail;
    SSHSecurity::revert()                    ? ++r.ok : ++r.fail;

    for (const auto& opt : SELinuxSecurity::modeOptions())
        SELinuxSecurity::revert(opt) ? ++r.ok : ++r.fail;
    for (const auto& opt : SELinuxSecurity::booleanOptions())
        SELinuxSecurity::revert(opt) ? ++r.ok : ++r.fail;

    for (const auto& opt : AppArmorSecurity::enforcementOptions())
        AppArmorSecurity::revert(opt) ? ++r.ok : ++r.fail;
    for (const auto& opt : AppArmorSecurity::profileOptions())
        AppArmorSecurity::revert(opt) ? ++r.ok : ++r.fail;

    return r;
}
