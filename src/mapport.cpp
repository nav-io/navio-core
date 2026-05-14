// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <mapport.h>

#include <clientversion.h>
#include <common/netif.h>
#include <common/pcp.h>
#include <common/system.h>
#include <logging.h>
#include <net.h>
#include <netaddress.h>
#include <netbase.h>
#include <random.h>
#include <util/thread.h>
#include <util/threadinterrupt.h>

#ifdef USE_UPNP
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
// The minimum supported miniUPnPc API version is set to 17. This excludes
// versions with known vulnerabilities.
static_assert(MINIUPNPC_API_VERSION >= 17, "miniUPnPc API version >= 17 assumed");
#endif // USE_UPNP

#include <atomic>
#include <cassert>
#include <chrono>
#include <functional>
#include <string>
#include <thread>

static CThreadInterrupt g_mapport_interrupt;
static std::thread g_mapport_thread;
static std::atomic_bool g_mapport_enabled_upnp{false};
static std::atomic_bool g_mapport_enabled_natpmp{false};

using namespace std::chrono_literals;
static constexpr auto PORT_MAPPING_REANNOUNCE_PERIOD{20min};
static constexpr auto PORT_MAPPING_RETRY_PERIOD{5min};

#ifdef USE_UPNP
static bool ProcessUpnp()
{
    bool ret = false;
    std::string port = strprintf("%u", GetListenPort());
    const char * multicastif = nullptr;
    const char * minissdpdpath = nullptr;
    struct UPNPDev * devlist = nullptr;
    char lanaddr[64];

    int error = 0;
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, 2, &error);

    struct UPNPUrls urls;
    struct IGDdatas data;
    int r;
#if MINIUPNPC_API_VERSION <= 17
    r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
#else
    r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr), nullptr, 0);
#endif
    if (r == 1)
    {
        if (fDiscover) {
            char externalIPAddress[40];
            r = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, externalIPAddress);
            if (r != UPNPCOMMAND_SUCCESS) {
                LogPrintf("UPnP: GetExternalIPAddress() returned %d\n", r);
            } else {
                if (externalIPAddress[0]) {
                    std::optional<CNetAddr> resolved{LookupHost(externalIPAddress, false)};
                    if (resolved.has_value()) {
                        LogPrintf("UPnP: ExternalIPAddress = %s\n", resolved->ToStringAddr());
                        AddLocal(resolved.value(), LOCAL_MAPPED);
                    }
                } else {
                    LogPrintf("UPnP: GetExternalIPAddress failed.\n");
                }
            }
        }

        std::string strDesc = PACKAGE_NAME " " + FormatFullVersion();

        do {
            r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", nullptr, "0");

            if (r != UPNPCOMMAND_SUCCESS) {
                ret = false;
                LogPrintf("AddPortMapping(%s, %s, %s) failed with code %d (%s)\n", port, port, lanaddr, r, strupnperror(r));
                break;
            } else {
                ret = true;
                LogPrintf("UPnP Port Mapping successful.\n");
            }
        } while (g_mapport_interrupt.sleep_for(PORT_MAPPING_REANNOUNCE_PERIOD));
        g_mapport_interrupt.reset();

        r = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port.c_str(), "TCP", nullptr);
        LogPrintf("UPNP_DeletePortMapping() returned: %d\n", r);
        freeUPNPDevlist(devlist); devlist = nullptr;
        FreeUPNPUrls(&urls);
    } else {
        LogPrintf("No valid UPnP IGDs found\n");
        freeUPNPDevlist(devlist); devlist = nullptr;
        if (r != 0)
            FreeUPNPUrls(&urls);
    }

    return ret;
}
#endif // USE_UPNP

static void ProcessPCP()
{
    // The same nonce is used for all mappings, this is allowed by the spec, and simplifies keeping track of them.
    PCPMappingNonce pcp_nonce;
    GetRandBytes(pcp_nonce);

    bool ret = false;
    bool no_resources = false;
    const uint16_t private_port = GetListenPort();
    // Multiply the reannounce period by two, as we'll try to renew approximately halfway.
    const uint32_t requested_lifetime = std::chrono::seconds(PORT_MAPPING_REANNOUNCE_PERIOD * 2).count();
    uint32_t actual_lifetime = 0;
    std::chrono::milliseconds sleep_time;

    // Local functor to handle result from PCP/NATPMP mapping.
    auto handle_mapping = [&](std::variant<MappingResult, MappingError> &res) -> void {
        if (MappingResult* mapping = std::get_if<MappingResult>(&res)) {
            LogPrintf("portmap: Added mapping %s\n", mapping->ToString());
            AddLocal(mapping->external, LOCAL_MAPPED);
            ret = true;
            actual_lifetime = std::min(actual_lifetime, mapping->lifetime);
        } else if (MappingError *err = std::get_if<MappingError>(&res)) {
            // Detailed error will already have been logged internally in respective Portmap function.
            if (*err == MappingError::NO_RESOURCES) {
                no_resources = true;
            }
        }
    };

    do {
        actual_lifetime = requested_lifetime;
        no_resources = false; // Set to true if there was any "no resources" error.
        ret = false; // Set to true if any mapping succeeds.

        // IPv4
        std::optional<CNetAddr> gateway4 = QueryDefaultGateway(NET_IPV4);
        if (!gateway4) {
            LogPrintf("portmap: Could not determine IPv4 default gateway\n");
        } else {
            LogPrintf("portmap: gateway [IPv4]: %s\n", gateway4->ToStringAddr());

            // Open a port mapping on whatever local address we have toward the gateway.
            struct in_addr inaddr_any;
            inaddr_any.s_addr = htonl(INADDR_ANY);
            auto res = PCPRequestPortMap(pcp_nonce, *gateway4, CNetAddr(inaddr_any), private_port, requested_lifetime, g_mapport_interrupt);
            MappingError* pcp_err = std::get_if<MappingError>(&res);
            if (pcp_err && *pcp_err == MappingError::UNSUPP_VERSION) {
                LogPrintf("portmap: Got unsupported PCP version response, falling back to NAT-PMP\n");
                res = NATPMPRequestPortMap(*gateway4, private_port, requested_lifetime, g_mapport_interrupt);
            }
            handle_mapping(res);
        }

        // IPv6
        std::optional<CNetAddr> gateway6 = QueryDefaultGateway(NET_IPV6);
        if (!gateway6) {
            LogPrintf("portmap: Could not determine IPv6 default gateway\n");
        } else {
            LogPrintf("portmap: gateway [IPv6]: %s\n", gateway6->ToStringAddr());

            // Try to open pinholes for all routable local IPv6 addresses.
            for (const auto &addr: GetLocalAddresses()) {
                if (!addr.IsRoutable() || !addr.IsIPv6()) continue;
                auto res = PCPRequestPortMap(pcp_nonce, *gateway6, addr, private_port, requested_lifetime, g_mapport_interrupt);
                handle_mapping(res);
            }
        }

        // Log message if we got NO_RESOURCES.
        if (no_resources) {
            LogPrintf("portmap: At least one mapping failed because of a NO_RESOURCES error. This usually indicates that the port is already used on the router. If this is the only instance of bitcoin running on the network, this will resolve itself automatically. Otherwise, you might want to choose a different P2P port to prevent this conflict.\n");
        }

        // Sanity-check returned lifetime.
        if (actual_lifetime < 30) {
            LogPrintf("portmap: Got impossibly short mapping lifetime of %d seconds\n", actual_lifetime);
            return;
        }
        // RFC6887 11.2.1 recommends that clients send their first renewal packet at a time chosen with uniform random
        // distribution in the range 1/2 to 5/8 of expiration time.
        std::chrono::seconds sleep_time_min(actual_lifetime / 2);
        std::chrono::seconds sleep_time_max(actual_lifetime * 5 / 8);
        auto sleep_range_ms = std::chrono::duration_cast<std::chrono::milliseconds>(sleep_time_max - sleep_time_min).count();
        sleep_time = sleep_time_min + std::chrono::milliseconds(FastRandomContext().randrange(static_cast<uint64_t>(sleep_range_ms)));
    } while (ret && g_mapport_interrupt.sleep_for(sleep_time));

    // We don't delete the mappings when the thread is interrupted because this would add additional complexity, so
    // we rather just choose a fairly short expiry time.
}

static void ThreadMapPort()
{
    do {
#ifdef USE_UPNP
        // High priority protocol: try UPnP first if enabled.
        if (g_mapport_enabled_upnp) {
            if (ProcessUpnp()) continue;
        }
#endif // USE_UPNP

        // PCP/NAT-PMP: run if natpmp is enabled.
        if (g_mapport_enabled_natpmp) {
            ProcessPCP();
        }

        if (!g_mapport_enabled_natpmp && !g_mapport_enabled_upnp) {
            return;
        }

    } while (g_mapport_interrupt.sleep_for(PORT_MAPPING_RETRY_PERIOD));
}

static void StartThreadMapPort()
{
    if (!g_mapport_thread.joinable()) {
        assert(!g_mapport_interrupt);
        g_mapport_thread = std::thread(&util::TraceThread, "mapport", &ThreadMapPort);
    }
}

void StartMapPort(bool use_upnp, bool use_natpmp)
{
    g_mapport_enabled_upnp = use_upnp;
    g_mapport_enabled_natpmp = use_natpmp;

    if (use_upnp || use_natpmp) {
        StartThreadMapPort();
    } else {
        InterruptMapPort();
        StopMapPort();
    }
}

void InterruptMapPort()
{
    g_mapport_enabled_upnp = false;
    g_mapport_enabled_natpmp = false;
    if (g_mapport_thread.joinable()) {
        g_mapport_interrupt();
    }
}

void StopMapPort()
{
    if (g_mapport_thread.joinable()) {
        g_mapport_thread.join();
        g_mapport_interrupt.reset();
    }
}
