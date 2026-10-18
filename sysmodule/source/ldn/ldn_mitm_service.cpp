/**
 * @file ldn_mitm_service.cpp
 * @brief LDN MITM Service implementation
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include "ldn_mitm_service.hpp"
#include "ldn_shared_state.hpp"
#include "../debug/log.hpp"
#include "../config/config_ipc_service.hpp"

namespace ams::mitm::ldn {

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
    // Evaluated each time a process opens ldn:u, so toggling [ldn] enabled
    // applies to the next game launch. When disabled, Atmosphere hands the
    // game the real ldn:u service (real local wireless).
    const bool enabled = ryu_ldn::ipc::IsLdnEnabled();
    LOG_INFO("LDN ShouldMitm called for pid=%lu, program_id=0x%016lx, enabled=%d",
             client_info.process_id.value, client_info.program_id.value, enabled);
    return enabled;
}

Result LdnMitMService::CreateUserLocalCommunicationService(
    sf::Out<sf::SharedPointer<ICommunicationInterface>> out)
{
    LOG_INFO("Creating UserLocalCommunicationService for program_id=0x%016lx", m_program_id.value);
    // Create our custom communication service with the client's program ID
    // The program_id is used to replace LocalCommunicationId=-1 with the real title ID
    auto service = sf::CreateSharedObjectEmplaced<ICommunicationInterface, ICommunicationService>(m_program_id);
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
