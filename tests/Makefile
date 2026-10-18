#---------------------------------------------------------------------------------
# ryu_ldn_nx - Unit Tests Makefile
#---------------------------------------------------------------------------------

# Compiler settings (host, not Switch)
CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -g -O0
CXXFLAGS += -I../sysmodule/source
CXXFLAGS += -DTEST_BUILD
LDFLAGS += -no-pie

# Host mbedTLS (libmbedtls-dev) for the wss:// transport
MBEDTLS_LIBS := -lmbedtls -lmbedx509 -lmbedcrypto

# Coverage flags (optional)
ifdef COVERAGE
CXXFLAGS += --coverage
LDFLAGS += --coverage
endif

#---------------------------------------------------------------------------------
# Source files
#---------------------------------------------------------------------------------
# Test sources
TEST_SOURCES := \
	protocol_tests.cpp \
	config_tests.cpp \
	config_manager_tests.cpp \
	log_tests.cpp \
	socket_tests.cpp \
	tcp_client_tests.cpp \
	wss_client_tests.cpp \
	connection_state_tests.cpp \
	reconnect_tests.cpp \
	client_tests.cpp \
	ldn_types_tests.cpp \
	ldn_state_machine_tests.cpp \
	ldn_proxy_tests.cpp \
	ldn_error_handling_tests.cpp \
	ldn_integration_tests.cpp \
	overlay_tests.cpp \
	ipc_config_tests.cpp \
	config_ipc_service_tests.cpp \
	shared_state_tests.cpp \
	ldn_packet_dispatcher_tests.cpp \
	ldn_session_handler_tests.cpp \
	ldn_proxy_handler_tests.cpp \
	ldn_handler_integration_tests.cpp \
	upnp_tests.cpp \
	p2p_proxy_tests.cpp \
	p2p_proxy_client_tests.cpp \
	p2p_integration_tests.cpp \
	p2p_create_network_tests.cpp \
	p2p_frame_tests.cpp \
	bsd_mitm_filter_tests.cpp \
	ldn_service_tests.cpp \
	bsd_proxy_tests.cpp

# Implementation sources needed for tests
IMPL_SOURCES := \
	../sysmodule/source/config/config.cpp \
	../sysmodule/source/config/config_manager.cpp \
	../sysmodule/source/debug/log.cpp \
	../sysmodule/source/network/socket.cpp \
	../sysmodule/source/network/tcp_client.cpp \
	../sysmodule/source/network/wss_client.cpp \
	../sysmodule/source/network/connection_state.cpp \
	../sysmodule/source/network/reconnect.cpp \
	../sysmodule/source/network/client.cpp

TEST_OBJECTS := $(TEST_SOURCES:.cpp=.o)
IMPL_OBJECTS := $(notdir $(IMPL_SOURCES:.cpp=.o))

# Targets
TARGET_PROTOCOL := run_protocol_tests
TARGET_CONFIG := run_config_tests
TARGET_CONFIG_MANAGER := run_config_manager_tests
TARGET_LOG := run_log_tests
TARGET_SOCKET := run_socket_tests
TARGET_TCP_CLIENT := run_tcp_client_tests
TARGET_WSS_CLIENT := run_wss_client_tests
TARGET_CONNECTION_STATE := run_connection_state_tests
TARGET_RECONNECT := run_reconnect_tests
TARGET_CLIENT := run_client_tests
TARGET_LDN_TYPES := run_ldn_types_tests
TARGET_LDN_STATE_MACHINE := run_ldn_state_machine_tests
TARGET_LDN_PROXY := run_ldn_proxy_tests
TARGET_LDN_ERROR := run_ldn_error_handling_tests
TARGET_LDN_INTEGRATION := run_ldn_integration_tests
TARGET_OVERLAY := run_overlay_tests
TARGET_IPC_CONFIG := run_ipc_config_tests
TARGET_CONFIG_IPC_SERVICE := run_config_ipc_service_tests
TARGET_SHARED_STATE := run_shared_state_tests
TARGET_PACKET_DISPATCHER := run_packet_dispatcher_tests
TARGET_SESSION_HANDLER := run_session_handler_tests
TARGET_PROXY_HANDLER := run_proxy_handler_tests
TARGET_HANDLER_INTEGRATION := run_handler_integration_tests
TARGET_UPNP := run_upnp_tests
TARGET_P2P_PROXY := run_p2p_proxy_tests
TARGET_P2P_CLIENT := run_p2p_proxy_client_tests
TARGET_P2P_INTEGRATION := run_p2p_integration_tests
TARGET_P2P_CREATE_NETWORK := run_p2p_create_network_tests
TARGET_P2P_FRAME := run_p2p_frame_tests
TARGET_BSD_MITM_FILTER := run_bsd_mitm_filter_tests
TARGET_LDN_SERVICE := run_ldn_service_tests
TARGET_BSD_PROXY := run_bsd_proxy_tests
TARGET_ALL := run_all_tests

#---------------------------------------------------------------------------------
# Build rules
#---------------------------------------------------------------------------------
.PHONY: all clean test test-protocol test-config test-config-manager test-log test-socket test-tcp-client test-wss-client test-connection-state test-reconnect test-client test-ldn-types test-ldn-state-machine test-ldn-proxy test-ldn-error test-ldn-integration test-overlay test-ipc-config test-config-ipc-service test-shared-state test-packet-dispatcher test-session-handler test-proxy-handler test-handler-integration test-upnp test-p2p-proxy test-p2p-client test-p2p-integration test-p2p-create-network test-bsd-mitm-filter coverage coverage-enforce coverage-full-enforce test-p2p-frame test-ldn-service test-bsd-proxy

all: $(TARGET_PROTOCOL) $(TARGET_CONFIG) $(TARGET_CONFIG_MANAGER) $(TARGET_LOG) $(TARGET_SOCKET) $(TARGET_TCP_CLIENT) $(TARGET_WSS_CLIENT) $(TARGET_CONNECTION_STATE) $(TARGET_RECONNECT) $(TARGET_CLIENT) $(TARGET_LDN_TYPES) $(TARGET_LDN_STATE_MACHINE) $(TARGET_LDN_PROXY) $(TARGET_LDN_ERROR) $(TARGET_LDN_INTEGRATION) $(TARGET_OVERLAY) $(TARGET_IPC_CONFIG) $(TARGET_CONFIG_IPC_SERVICE) $(TARGET_SHARED_STATE) $(TARGET_PACKET_DISPATCHER) $(TARGET_SESSION_HANDLER) $(TARGET_PROXY_HANDLER) $(TARGET_HANDLER_INTEGRATION) $(TARGET_UPNP) $(TARGET_P2P_PROXY) $(TARGET_P2P_CLIENT) $(TARGET_P2P_INTEGRATION) $(TARGET_BSD_MITM_FILTER) $(TARGET_P2P_FRAME) $(TARGET_LDN_SERVICE) $(TARGET_BSD_PROXY)

# Protocol tests (header-only, no impl needed)
$(TARGET_PROTOCOL): protocol_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Config tests (needs config.cpp impl)
$(TARGET_CONFIG): config_tests.o config.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Config Manager tests (needs config.cpp and config_manager.cpp)
$(TARGET_CONFIG_MANAGER): config_manager_tests.o config_manager.o config.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Log tests (needs log.cpp and config.cpp impl)
$(TARGET_LOG): log_tests.o log.o config.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Socket tests (needs socket.cpp, log.cpp for logging)
$(TARGET_SOCKET): socket_tests.o socket.o log.o config.o
	$(CXX) $(LDFLAGS) -o $@ $^

# TCP Client tests (needs socket.cpp, tcp_client.cpp, and log.cpp for logging)
$(TARGET_TCP_CLIENT): tcp_client_tests.o tcp_client.o socket.o log.o config.o
	$(CXX) $(LDFLAGS) -o $@ $^

# WssClient tests (needs mbedTLS and the certificates generated below)
$(TARGET_WSS_CLIENT): wss_client_tests.o wss_client.o tcp_client.o socket.o log.o config.o | wss_certs
	$(CXX) $(LDFLAGS) -o $@ $^ $(MBEDTLS_LIBS) -lpthread

# Connection State tests (needs connection_state.cpp)
$(TARGET_CONNECTION_STATE): connection_state_tests.o connection_state.o log.o config.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Reconnect tests (needs reconnect.cpp)
$(TARGET_RECONNECT): reconnect_tests.o reconnect.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Client tests (needs all network modules and log.cpp for logging)
$(TARGET_CLIENT): client_tests.o client.o tcp_client.o wss_client.o socket.o connection_state.o reconnect.o config.o log.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(MBEDTLS_LIBS)

# LDN Types tests (header-only, no impl needed)
$(TARGET_LDN_TYPES): ldn_types_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# LDN State Machine tests (standalone test implementation)
$(TARGET_LDN_STATE_MACHINE): ldn_state_machine_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# LDN Proxy tests (header-only, no impl needed)
$(TARGET_LDN_PROXY): ldn_proxy_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# LDN Error Handling tests (standalone test implementation)
$(TARGET_LDN_ERROR): ldn_error_handling_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# LDN Integration tests (standalone end-to-end tests)
$(TARGET_LDN_INTEGRATION): ldn_integration_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Overlay tests (mocked Switch environment)
$(TARGET_OVERLAY): overlay_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# IPC Config tests (extended config commands)
$(TARGET_IPC_CONFIG): ipc_config_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Config IPC Service tests (ryu:cfg standalone service)
$(TARGET_CONFIG_IPC_SERVICE): config_ipc_service_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# SharedState tests (standalone test implementation)
$(TARGET_SHARED_STATE): shared_state_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Packet Dispatcher tests (needs ldn_packet_dispatcher.cpp)
$(TARGET_PACKET_DISPATCHER): ldn_packet_dispatcher_tests.o ldn_packet_dispatcher.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Session Handler tests (needs ldn_session_handler.cpp)
$(TARGET_SESSION_HANDLER): ldn_session_handler_tests.o ldn_session_handler.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Proxy Handler tests (needs ldn_proxy_handler.cpp)
$(TARGET_PROXY_HANDLER): ldn_proxy_handler_tests.o ldn_proxy_handler.o
	$(CXX) $(LDFLAGS) -o $@ $^

# Handler Integration tests (needs all handler implementations)
$(TARGET_HANDLER_INTEGRATION): ldn_handler_integration_tests.o ldn_packet_dispatcher.o ldn_session_handler.o ldn_proxy_handler.o
	$(CXX) $(LDFLAGS) -o $@ $^

# UPnP tests (standalone, no miniupnpc needed for mock tests)
$(TARGET_UPNP): upnp_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# P2P Proxy tests (standalone, tests constants and logic)
$(TARGET_P2P_PROXY): p2p_proxy_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# P2P Proxy Client tests (standalone, tests constants and logic)
$(TARGET_P2P_CLIENT): p2p_proxy_client_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# P2P Integration tests (Story 9.7 - HandleExternalProxy integration)
$(TARGET_P2P_INTEGRATION): p2p_integration_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# P2P CreateNetwork tests (Story 9.8 - CreateNetwork with P2P)
$(TARGET_P2P_CREATE_NETWORK): p2p_create_network_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# P2P frame parser tests (header-only real code: p2p/p2p_frame.hpp)
$(TARGET_P2P_FRAME): p2p_frame_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# BSD MITM filter tests (standalone, mirrors ShouldMitm program filter)
$(TARGET_BSD_MITM_FILTER): bsd_mitm_filter_tests.o
	$(CXX) $(LDFLAGS) -o $@ $^

# LDN service regression tests: real host-safe ldn/ sources, built against
# the minimal stratosphere shim in shim/
$(TARGET_LDN_SERVICE): ldn_service_tests.o ldn_network_timeout.o log.o config.o
	$(CXX) $(LDFLAGS) -pthread -o $@ $^

ldn_service_tests.o ldn_network_timeout.o: CXXFLAGS += -Ishim -pthread
# BSD proxy tests (real bsd/ sources, built against tests/host_shim)
# AddressSanitizer catches use-after-free in the proxy socket lifetime tests.
BSD_PROXY_SANITIZE := -fsanitize=address -fno-omit-frame-pointer
BSD_PROXY_CXXFLAGS := $(CXXFLAGS) -Ihost_shim -pthread $(BSD_PROXY_SANITIZE)
BSD_PROXY_OBJECTS := bsd_proxy_socket.o bsd_proxy_socket_manager.o bsd_ephemeral_port_pool.o

$(TARGET_BSD_PROXY): bsd_proxy_tests.o $(BSD_PROXY_OBJECTS) log.o config.o
	$(CXX) $(LDFLAGS) -pthread $(BSD_PROXY_SANITIZE) -o $@ $^

bsd_proxy_tests.o: bsd_proxy_tests.cpp host_shim/stratosphere.hpp
	$(CXX) $(BSD_PROXY_CXXFLAGS) -c -o $@ $<

bsd_proxy_socket.o: ../sysmodule/source/bsd/proxy_socket.cpp
	$(CXX) $(BSD_PROXY_CXXFLAGS) -c -o $@ $<

bsd_proxy_socket_manager.o: ../sysmodule/source/bsd/proxy_socket_manager.cpp
	$(CXX) $(BSD_PROXY_CXXFLAGS) -c -o $@ $<

bsd_ephemeral_port_pool.o: ../sysmodule/source/bsd/ephemeral_port_pool.cpp
	$(CXX) $(BSD_PROXY_CXXFLAGS) -c -o $@ $<

# Compile test sources
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Compile implementation sources
config.o: ../sysmodule/source/config/config.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

config_manager.o: ../sysmodule/source/config/config_manager.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

log.o: ../sysmodule/source/debug/log.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

socket.o: ../sysmodule/source/network/socket.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

tcp_client.o: ../sysmodule/source/network/tcp_client.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

wss_client.o: ../sysmodule/source/network/wss_client.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Test PKI for the WssClient suite: ca.pem signs a localhost certificate,
# other_ca.pem is an unrelated CA for the bad-certificate test.
wss_certs:
	mkdir -p $@.tmp
	printf 'subjectAltName=DNS:localhost\n' > $@.tmp/san.ext
	openssl ecparam -name prime256v1 -genkey -noout -out $@.tmp/ca.key
	openssl req -x509 -new -key $@.tmp/ca.key -sha256 -days 3650 -subj /CN=ryu_ldn_nx-test-ca -out $@.tmp/ca.pem
	openssl ecparam -name prime256v1 -genkey -noout -out $@.tmp/other_ca.key
	openssl req -x509 -new -key $@.tmp/other_ca.key -sha256 -days 3650 -subj /CN=ryu_ldn_nx-other-ca -out $@.tmp/other_ca.pem
	openssl ecparam -name prime256v1 -genkey -noout -out $@.tmp/server.key
	openssl req -new -key $@.tmp/server.key -subj /CN=localhost -out $@.tmp/server.csr
	openssl x509 -req -in $@.tmp/server.csr -CA $@.tmp/ca.pem -CAkey $@.tmp/ca.key -CAcreateserial \
		-sha256 -days 3650 -extfile $@.tmp/san.ext -out $@.tmp/server.pem
	mv $@.tmp $@

connection_state.o: ../sysmodule/source/network/connection_state.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

reconnect.o: ../sysmodule/source/network/reconnect.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

client.o: ../sysmodule/source/network/client.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

ldn_packet_dispatcher.o: ../sysmodule/source/ldn/ldn_packet_dispatcher.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

ldn_session_handler.o: ../sysmodule/source/ldn/ldn_session_handler.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

ldn_proxy_handler.o: ../sysmodule/source/ldn/ldn_proxy_handler.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

ldn_network_timeout.o: ../sysmodule/source/ldn/ldn_network_timeout.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Run all tests
test: $(TARGET_PROTOCOL) $(TARGET_CONFIG) $(TARGET_CONFIG_MANAGER) $(TARGET_LOG) $(TARGET_SOCKET) $(TARGET_TCP_CLIENT) $(TARGET_WSS_CLIENT) $(TARGET_CONNECTION_STATE) $(TARGET_RECONNECT) $(TARGET_CLIENT) $(TARGET_LDN_TYPES) $(TARGET_LDN_STATE_MACHINE) $(TARGET_LDN_PROXY) $(TARGET_LDN_ERROR) $(TARGET_LDN_INTEGRATION) $(TARGET_OVERLAY) $(TARGET_IPC_CONFIG) $(TARGET_CONFIG_IPC_SERVICE) $(TARGET_SHARED_STATE) $(TARGET_PACKET_DISPATCHER) $(TARGET_SESSION_HANDLER) $(TARGET_PROXY_HANDLER) $(TARGET_HANDLER_INTEGRATION) $(TARGET_UPNP) $(TARGET_P2P_PROXY) $(TARGET_P2P_CLIENT) $(TARGET_P2P_INTEGRATION) $(TARGET_P2P_CREATE_NETWORK) $(TARGET_BSD_MITM_FILTER) $(TARGET_P2P_FRAME) $(TARGET_LDN_SERVICE) $(TARGET_BSD_PROXY)
	@echo "=== Running Protocol Tests ==="
	./$(TARGET_PROTOCOL)
	@echo ""
	@echo "=== Running Config Tests ==="
	./$(TARGET_CONFIG)
	@echo ""
	@echo "=== Running Config Manager Tests ==="
	./$(TARGET_CONFIG_MANAGER)
	@echo ""
	@echo "=== Running Log Tests ==="
	./$(TARGET_LOG)
	@echo ""
	@echo "=== Running Socket Tests ==="
	./$(TARGET_SOCKET)
	@echo ""
	@echo "=== Running TcpClient Tests ==="
	./$(TARGET_TCP_CLIENT)
	@echo ""
	@echo "=== Running WssClient Tests ==="
	./$(TARGET_WSS_CLIENT)
	@echo ""
	@echo "=== Running Connection State Tests ==="
	./$(TARGET_CONNECTION_STATE)
	@echo ""
	@echo "=== Running Reconnect Tests ==="
	./$(TARGET_RECONNECT)
	@echo ""
	@echo "=== Running Client Tests ==="
	./$(TARGET_CLIENT)
	@echo ""
	@echo "=== Running LDN Types Tests ==="
	./$(TARGET_LDN_TYPES)
	@echo ""
	@echo "=== Running LDN State Machine Tests ==="
	./$(TARGET_LDN_STATE_MACHINE)
	@echo ""
	@echo "=== Running LDN Proxy Tests ==="
	./$(TARGET_LDN_PROXY)
	@echo ""
	@echo "=== Running LDN Error Handling Tests ==="
	./$(TARGET_LDN_ERROR)
	@echo ""
	@echo "=== Running LDN Integration Tests ==="
	./$(TARGET_LDN_INTEGRATION)
	@echo ""
	@echo "=== Running Overlay Tests ==="
	./$(TARGET_OVERLAY)
	@echo ""
	@echo "=== Running IPC Config Tests ==="
	./$(TARGET_IPC_CONFIG)
	@echo ""
	@echo "=== Running Config IPC Service Tests ==="
	./$(TARGET_CONFIG_IPC_SERVICE)
	@echo ""
	@echo "=== Running SharedState Tests ==="
	./$(TARGET_SHARED_STATE)
	@echo ""
	@echo "=== Running Packet Dispatcher Tests ==="
	./$(TARGET_PACKET_DISPATCHER)
	@echo ""
	@echo "=== Running Session Handler Tests ==="
	./$(TARGET_SESSION_HANDLER)
	@echo ""
	@echo "=== Running Proxy Handler Tests ==="
	./$(TARGET_PROXY_HANDLER)
	@echo ""
	@echo "=== Running Handler Integration Tests ==="
	./$(TARGET_HANDLER_INTEGRATION)
	@echo ""
	@echo "=== Running UPnP Tests ==="
	./$(TARGET_UPNP)
	@echo ""
	@echo "=== Running P2P Proxy Tests ==="
	./$(TARGET_P2P_PROXY)
	@echo ""
	@echo "=== Running P2P Proxy Client Tests ==="
	./$(TARGET_P2P_CLIENT)
	@echo ""
	@echo "=== Running P2P Integration Tests ==="
	./$(TARGET_P2P_INTEGRATION)
	@echo ""
	@echo "=== Running P2P CreateNetwork Tests ==="
	./$(TARGET_P2P_CREATE_NETWORK)
	@echo ""
	@echo "=== Running P2P Frame Tests ==="
	./$(TARGET_P2P_FRAME)
	@echo ""
	@echo "=== Running BSD MITM Filter Tests ==="
	./$(TARGET_BSD_MITM_FILTER)
	@echo ""
	@echo "=== Running LDN Service Tests ==="
	./$(TARGET_LDN_SERVICE)
	@echo "=== Running BSD Proxy Tests ==="
	./$(TARGET_BSD_PROXY)

test-protocol: $(TARGET_PROTOCOL)
	./$(TARGET_PROTOCOL)

test-config: $(TARGET_CONFIG)
	./$(TARGET_CONFIG)

test-config-manager: $(TARGET_CONFIG_MANAGER)
	./$(TARGET_CONFIG_MANAGER)

test-log: $(TARGET_LOG)
	./$(TARGET_LOG)

test-socket: $(TARGET_SOCKET)
	./$(TARGET_SOCKET)

test-tcp-client: $(TARGET_TCP_CLIENT)
	./$(TARGET_TCP_CLIENT)

test-wss-client: $(TARGET_WSS_CLIENT)
	./$(TARGET_WSS_CLIENT)

test-connection-state: $(TARGET_CONNECTION_STATE)
	./$(TARGET_CONNECTION_STATE)

test-reconnect: $(TARGET_RECONNECT)
	./$(TARGET_RECONNECT)

test-client: $(TARGET_CLIENT)
	./$(TARGET_CLIENT)

test-ldn-types: $(TARGET_LDN_TYPES)
	./$(TARGET_LDN_TYPES)

test-ldn-state-machine: $(TARGET_LDN_STATE_MACHINE)
	./$(TARGET_LDN_STATE_MACHINE)

test-ldn-proxy: $(TARGET_LDN_PROXY)
	./$(TARGET_LDN_PROXY)

test-ldn-error: $(TARGET_LDN_ERROR)
	./$(TARGET_LDN_ERROR)

test-ldn-integration: $(TARGET_LDN_INTEGRATION)
	./$(TARGET_LDN_INTEGRATION)

test-overlay: $(TARGET_OVERLAY)
	./$(TARGET_OVERLAY)

test-ipc-config: $(TARGET_IPC_CONFIG)
	./$(TARGET_IPC_CONFIG)

test-config-ipc-service: $(TARGET_CONFIG_IPC_SERVICE)
	./$(TARGET_CONFIG_IPC_SERVICE)

test-shared-state: $(TARGET_SHARED_STATE)
	./$(TARGET_SHARED_STATE)

test-packet-dispatcher: $(TARGET_PACKET_DISPATCHER)
	./$(TARGET_PACKET_DISPATCHER)

test-session-handler: $(TARGET_SESSION_HANDLER)
	./$(TARGET_SESSION_HANDLER)

test-proxy-handler: $(TARGET_PROXY_HANDLER)
	./$(TARGET_PROXY_HANDLER)

test-handler-integration: $(TARGET_HANDLER_INTEGRATION)
	./$(TARGET_HANDLER_INTEGRATION)

test-upnp: $(TARGET_UPNP)
	./$(TARGET_UPNP)

test-p2p-proxy: $(TARGET_P2P_PROXY)
	./$(TARGET_P2P_PROXY)

test-p2p-client: $(TARGET_P2P_CLIENT)
	./$(TARGET_P2P_CLIENT)

test-p2p-integration: $(TARGET_P2P_INTEGRATION)
	./$(TARGET_P2P_INTEGRATION)

test-p2p-create-network: $(TARGET_P2P_CREATE_NETWORK)
	./$(TARGET_P2P_CREATE_NETWORK)

test-p2p-frame: $(TARGET_P2P_FRAME)
	./$(TARGET_P2P_FRAME)

test-bsd-mitm-filter: $(TARGET_BSD_MITM_FILTER)
	./$(TARGET_BSD_MITM_FILTER)

test-ldn-service: $(TARGET_LDN_SERVICE)
	./$(TARGET_LDN_SERVICE)
test-bsd-proxy: $(TARGET_BSD_PROXY)
	./$(TARGET_BSD_PROXY)

coverage: clean
	$(MAKE) COVERAGE=1 test
	gcov $(TEST_SOURCES)
	@echo "Coverage report generated"

# Enforce minimum coverage threshold (default 80%)
# Requires: gcovr (pip install gcovr)
# Usage: make COVERAGE=1 coverage-enforce
#        make COVERAGE=1 coverage-enforce MIN_COVERAGE=90
MIN_COVERAGE ?= 80

coverage-enforce: coverage
	@echo "=== Checking per-file coverage (minimum $(MIN_COVERAGE)%) ==="
	cd .. && python3 scripts/check-coverage.py --min $(MIN_COVERAGE) --root .

# Full coverage: unit tests + integration tests against Docker LDN server
# Builds everything with --coverage, runs unit tests, then fires up the
# Docker LdnServer and runs integration tests, finally reports per-file
# line coverage for the 5 network source files.
COV_NETWORK_SOURCES := \
	client.cpp \
	tcp_client.cpp \
	connection_state.cpp \
	reconnect.cpp \
	socket.cpp

coverage-full: clean
	@echo "=== Phase 1: Unit tests with coverage ==="
	$(MAKE) COVERAGE=1 test
	@echo ""
	@echo "=== Phase 2: Integration tests with coverage ==="
	$(MAKE) -C integration COV=1 clean all
	cd integration && bash prepare-compose.sh
	docker compose -f integration/docker-compose.yml up -d
	bash integration/wait-for-server.sh localhost 30456 60
	sleep 2
	INTEGRATION_COMPOSE_FILE="$$(pwd)/integration/docker-compose.yml" \
		./integration/run_integration_tests localhost 30456 ; \
		int_exit=$$? ; \
	echo "" ; \
	echo "=== Stopping LdnServer ===" ; \
	docker compose -f integration/docker-compose.yml down -v ; \
	exit $$int_exit

# Full coverage enforcement: unit + integration tests + per-file threshold check
# Requires: Docker (for LdnServer), gcovr (pip install gcovr)
# Usage: make coverage-full-enforce
#        make coverage-full-enforce MIN_COVERAGE=90
coverage-full-enforce: clean
	@echo "=== Phase 1: Unit tests with coverage ==="
	$(MAKE) COVERAGE=1 test
	@echo ""
	@echo "=== Phase 2: Integration tests with coverage ==="
	$(MAKE) -C integration COV=1 clean all
	cd integration && bash prepare-compose.sh
	docker compose -f integration/docker-compose.yml up -d
	bash integration/wait-for-server.sh localhost 30456 60
	sleep 2
	INTEGRATION_COMPOSE_FILE="$$(pwd)/integration/docker-compose.yml" \
		./integration/run_integration_tests localhost 30456 || true
	@echo ""
	@echo "=== Phase 3: Stopping LdnServer ==="
	docker compose -f integration/docker-compose.yml down -v
	@echo ""
	@echo "=== Phase 4: Checking per-file coverage (minimum $(MIN_COVERAGE)%) ==="
	cd .. && python3 scripts/check-coverage.py --min $(MIN_COVERAGE) --root .

clean:
	rm -f *.o $(TARGET_PROTOCOL) $(TARGET_CONFIG) $(TARGET_CONFIG_MANAGER) $(TARGET_LOG) $(TARGET_SOCKET) $(TARGET_TCP_CLIENT) $(TARGET_WSS_CLIENT) $(TARGET_CONNECTION_STATE) $(TARGET_RECONNECT) $(TARGET_CLIENT) $(TARGET_LDN_TYPES) $(TARGET_LDN_STATE_MACHINE) $(TARGET_LDN_PROXY) $(TARGET_LDN_ERROR) $(TARGET_LDN_INTEGRATION) $(TARGET_OVERLAY) $(TARGET_IPC_CONFIG) $(TARGET_CONFIG_IPC_SERVICE) $(TARGET_SHARED_STATE) $(TARGET_PACKET_DISPATCHER) $(TARGET_SESSION_HANDLER) $(TARGET_PROXY_HANDLER) $(TARGET_HANDLER_INTEGRATION) $(TARGET_UPNP) $(TARGET_P2P_PROXY) $(TARGET_P2P_CLIENT) $(TARGET_P2P_INTEGRATION) $(TARGET_P2P_CREATE_NETWORK) $(TARGET_BSD_MITM_FILTER) $(TARGET_P2P_FRAME) $(TARGET_LDN_SERVICE) $(TARGET_BSD_PROXY)
	rm -f *.gcno *.gcda *.gcov
	rm -rf wss_certs wss_certs.tmp

#---------------------------------------------------------------------------------
# Dependencies
#---------------------------------------------------------------------------------
protocol_tests.o: protocol_tests.cpp \
	../sysmodule/source/protocol/types.hpp \
	../sysmodule/source/protocol/ryu_protocol.hpp \
	../sysmodule/source/protocol/packet_buffer.hpp

config_tests.o: config_tests.cpp \
	../sysmodule/source/config/config.hpp

config.o: ../sysmodule/source/config/config.cpp \
	../sysmodule/source/config/config.hpp

config_manager_tests.o: config_manager_tests.cpp \
	../sysmodule/source/config/config_manager.hpp \
	../sysmodule/source/config/config.hpp

config_manager.o: ../sysmodule/source/config/config_manager.cpp \
	../sysmodule/source/config/config_manager.hpp \
	../sysmodule/source/config/config.hpp

log_tests.o: log_tests.cpp \
	../sysmodule/source/debug/log.hpp \
	../sysmodule/source/config/config.hpp

log.o: ../sysmodule/source/debug/log.cpp \
	../sysmodule/source/debug/log.hpp \
	../sysmodule/source/config/config.hpp

socket_tests.o: socket_tests.cpp \
	../sysmodule/source/network/socket.hpp

socket.o: ../sysmodule/source/network/socket.cpp \
	../sysmodule/source/network/socket.hpp

tcp_client_tests.o: tcp_client_tests.cpp \
	../sysmodule/source/network/tcp_client.hpp \
	../sysmodule/source/network/socket.hpp \
	../sysmodule/source/protocol/ryu_protocol.hpp \
	../sysmodule/source/protocol/packet_buffer.hpp

tcp_client.o: ../sysmodule/source/network/tcp_client.cpp \
	../sysmodule/source/network/tcp_client.hpp \
	../sysmodule/source/network/socket.hpp \
	../sysmodule/source/protocol/ryu_protocol.hpp \
	../sysmodule/source/protocol/packet_buffer.hpp

wss_client_tests.o: wss_client_tests.cpp \
	../sysmodule/source/network/wss_client.hpp \
	../sysmodule/source/network/tcp_client.hpp

wss_client.o: ../sysmodule/source/network/wss_client.cpp \
	../sysmodule/source/network/wss_client.hpp \
	../sysmodule/source/network/tcp_client.hpp \
	../sysmodule/source/config/config.hpp

connection_state_tests.o: connection_state_tests.cpp \
	../sysmodule/source/network/connection_state.hpp

connection_state.o: ../sysmodule/source/network/connection_state.cpp \
	../sysmodule/source/network/connection_state.hpp

reconnect_tests.o: reconnect_tests.cpp \
	../sysmodule/source/network/reconnect.hpp

reconnect.o: ../sysmodule/source/network/reconnect.cpp \
	../sysmodule/source/network/reconnect.hpp

client_tests.o: client_tests.cpp \
	../sysmodule/source/network/client.hpp \
	../sysmodule/source/network/itcp_client.hpp \
	../sysmodule/source/network/tcp_client.hpp \
	../sysmodule/source/network/connection_state.hpp \
	../sysmodule/source/network/reconnect.hpp \
	mock_tcp_client.hpp

client.o: ../sysmodule/source/network/client.cpp \
	../sysmodule/source/network/client.hpp \
	../sysmodule/source/network/tcp_client.hpp \
	../sysmodule/source/network/connection_state.hpp \
	../sysmodule/source/network/reconnect.hpp

ldn_types_tests.o: ldn_types_tests.cpp \
	../sysmodule/source/protocol/types.hpp

ldn_state_machine_tests.o: ldn_state_machine_tests.cpp

ldn_proxy_tests.o: ldn_proxy_tests.cpp \
	../sysmodule/source/protocol/types.hpp

ldn_error_handling_tests.o: ldn_error_handling_tests.cpp

ldn_integration_tests.o: ldn_integration_tests.cpp

overlay_tests.o: overlay_tests.cpp

ipc_config_tests.o: ipc_config_tests.cpp

config_ipc_service_tests.o: config_ipc_service_tests.cpp

p2p_frame_tests.o: p2p_frame_tests.cpp \
	../sysmodule/source/p2p/p2p_frame.hpp \
	../sysmodule/source/protocol/ryu_protocol.hpp

# DNS wrapper tests (include dns_wrap.cpp directly for its internal functions).
# Hooked into all/test/clean as extra prerequisites so the shared lines
# above stay untouched.
TARGET_DNS_WRAP := run_dns_wrap_tests
$(TARGET_DNS_WRAP): dns_wrap_tests.o log.o config.o
	$(CXX) $(LDFLAGS) -o $@ $^

dns_wrap_tests.o: dns_wrap_tests.cpp ../sysmodule/source/network/dns_wrap.cpp

.PHONY: test-dns-wrap clean-dns-wrap
test-dns-wrap: $(TARGET_DNS_WRAP)
	@echo ""
	@echo "=== Running DNS Wrapper Tests ==="
	./$(TARGET_DNS_WRAP)

clean-dns-wrap:
	rm -f $(TARGET_DNS_WRAP)

all: $(TARGET_DNS_WRAP)
test: test-dns-wrap
clean: clean-dns-wrap

# Real p2p/ proxy sources against tests/host_shim (C++20 for constinit)
TARGET_P2P_LOCK := run_p2p_lock_tests
P2P_LOCK_CXXFLAGS := $(CXXFLAGS) -std=c++20 -Ihost_shim -pthread

$(TARGET_P2P_LOCK): p2p_lock_tests.o p2p_client_real.o p2p_server_real.o log.o config.o
	$(CXX) $(LDFLAGS) -pthread -o $@ $^

p2p_lock_tests.o: p2p_lock_tests.cpp host_shim/stratosphere.hpp
	$(CXX) $(P2P_LOCK_CXXFLAGS) -c -o $@ $<

p2p_client_real.o: ../sysmodule/source/p2p/p2p_proxy_client.cpp host_shim/stratosphere.hpp
	$(CXX) $(P2P_LOCK_CXXFLAGS) -c -o $@ $<

p2p_server_real.o: ../sysmodule/source/p2p/p2p_proxy_server.cpp host_shim/stratosphere.hpp
	$(CXX) $(P2P_LOCK_CXXFLAGS) -c -o $@ $<

.PHONY: test-p2p-lock clean-p2p-lock
test-p2p-lock: $(TARGET_P2P_LOCK)
	@echo ""
	@echo "=== Running P2P Lock Tests ==="
	./$(TARGET_P2P_LOCK)

clean-p2p-lock:
	rm -f $(TARGET_P2P_LOCK)

all: $(TARGET_P2P_LOCK)
test: test-p2p-lock
clean: clean-p2p-lock
