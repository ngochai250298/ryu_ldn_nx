/**
 * @file ldn_mitm_service.cpp
 * @brief LDN MITM Service implementation
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include "ldn_mitm_service.hpp"
#include "ldn_shared_state.hpp"
#include "ldn_helpers.hpp"
#include "../debug/log.hpp"
#include "ldn_route.hpp"
#include "../config/config_ipc_service.hpp"

namespace ams::mitm::ldn {

static_assert(ryu_ldn::ldn::RealWirelessKey == HidNpadButton_ZR);

LdnMitMService::LdnMitMService(std::shared_ptr<::Service>&& s, const sm::MitmProcessInfo& c)
    : MitmServiceImplBase(std::forward<std::shared_ptr<::Service>>(s), c)
    , m_program_id(c.program_id)
    , m_client_pid(c.process_id.value)
{
    LOG_INFO("LDN MITM service created for program_id=0x%016lx, pid=%lu",
             c.program_id.value, m_client_pid);

    // Register PID immediately so BSD MITM can intercept this process
    // This happens BEFORE Initialize() is called
    SharedState::GetInstance().SetLdnPid(m_client_pid);
}

LdnMitMService::~LdnMitMService() {
    LOG_INFO("LDN MITM service destroyed for program_id=0x%016lx, pid=%lu",
             m_program_id.value, m_client_pid);

    // NOTE: Do NOT clear LDN PID here!
    // LdnMitMService is a factory that creates ICommunicationService, and is destroyed
    // right after. The ICommunicationService continues to live and the game will
    // open BSD sockets later. The PID must remain set so BSD MITM can intercept.
    // The PID will be cleared when ICommunicationService is destroyed.
}

bool LdnMitMService::ShouldMitm(const sm::MitmProcessInfo& client_info) {
    // We always want to intercept LDN calls from applications.
    // Relay or real radio is decided per session in
    // CreateUserLocalCommunicationService (no IPC here: sm waits on us).
    LOG_INFO("LDN ShouldMitm called for pid=%lu, program_id=0x%016lx",
             client_info.process_id.value, client_info.program_id.value);
    return true;
}

Result LdnMitMService::CreateUserLocalCommunicationService(
    sf::Out<sf::SharedPointer<ICommunicationInterface>> out)
{
    // Decided each time the game starts Local Wireless, like ldn_mitm's
    // enable switch: forwarding hands the game Nintendo's real service.
    u32 ip = 0;
    const bool online = R_SUCCEEDED(nifmGetCurrentIpAddress(&ip)) && ip != 0;
    const bool enabled = ryu_ldn::ipc::IsLdnEnabled();
    const u64 keys = m_client_info.override_status.GetKeysHeld();
    const bool relay = ryu_ldn::ldn::UseRelay(enabled, online, keys);
    LOG_INFO("CreateUserLocalCommunicationService: program_id=0x%016lx enabled=%d online=%d keys=0x%lx -> %s",
             m_program_id.value, enabled, online, keys, relay ? "relay" : "real wireless");

    SharedState::GetInstance().SetRealWirelessPid(relay ? 0 : m_client_pid);
    R_UNLESS(relay, sm::mitm::ResultShouldForwardToSession());

    // Create our custom communication service with the client's program ID
    // The program_id is used to replace LocalCommunicationId=-1 with the real title ID
    // Each instance runs its receive thread on its own stack; refuse rather
    // than share one if every stack is still held by a live instance.
    const int stack_slot = ICommunicationService::ClaimReceiveStack();
    if (stack_slot < 0) {
        LOG_ERROR("CreateUserLocalCommunicationService: no free receive stack, refusing session");
        R_RETURN(MAKERESULT(helpers::desc::Module, helpers::desc::InvalidState));
    }
    auto service = sf::CreateSharedObjectEmplaced<ICommunicationInterface, ICommunicationService>(
        m_program_id, m_client_pid, stack_slot);
    out.SetValue(std::move(service));
    R_SUCCEED();
}

Result LdnMitMService::CreateClientProcessMonitor(
    sf::Out<sf::SharedPointer<IClientProcessMonitorInterface>> out)
{
    LOG_INFO("Creating ClientProcessMonitor");
    // Required for firmware 18.0.0+ compatibility
    auto monitor = sf::CreateSharedObjectEmplaced<IClientProcessMonitorInterface, IClientProcessMonitor>();
    out.SetValue(std::move(monitor));
    R_SUCCEED();
}

} // namespace ams::mitm::ldn
