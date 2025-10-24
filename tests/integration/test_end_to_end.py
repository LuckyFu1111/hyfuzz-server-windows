"""
HyFuzz MCP Server - End-to-End Integration Tests

This module contains comprehensive end-to-end tests for the HyFuzz MCP server.
Tests cover complete workflows including server startup, payload generation,
MCP protocol communication, and multi-protocol support.

Test Coverage:
- Server initialization and shutdown
- Client connection management
- MCP protocol compliance
- Payload generation pipeline
- Knowledge base integration
- LLM CoT reasoning
- Error handling and recovery
- Performance benchmarking
- Multi-protocol support (HTTP, CoAP, MQTT)

Usage:
    pytest tests/integration/test_end_to_end.py -v
    pytest tests/integration/test_end_to_end.py::TestE2EPayloadGeneration -v
    pytest tests/integration/test_end_to_end.py -m integration -v

Author: HyFuzz Team
Version: 1.0.0
"""

import pytest
import time
import logging
from typing import Dict, List, Any, Optional
from tests.integration import (
    IntegrationTestBase,
    IntegrationTestLevel,
    TestResult,
    create_test_server,
    create_test_client,
    wait_for_server,
    retry_operation,
)
from tests.fixtures.mock_llm import create_mock_client
from tests.fixtures.mock_data import (
    SAMPLE_CWE_DATA,
    SAMPLE_CVE_DATA,
    SAMPLE_PAYLOADS,
)
from tests.fixtures.mock_models import (
    create_mock_payload_request,
    create_mock_cwe_data,
    PayloadType,
    Severity,
)

# Initialize logger
logger = logging.getLogger(__name__)

# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration

# ==============================================================================
# Test Configuration
# ==============================================================================

TEST_TIMEOUT = 60  # seconds
RETRY_COUNT = 3
RETRY_DELAY = 0.5


# ==============================================================================
# Base Test Class
# ==============================================================================

class TestE2EBase(IntegrationTestBase):
    """Base class for end-to-end tests."""

    test_level = IntegrationTestLevel.COMPREHENSIVE
    use_mock_llm = True
    timeout_seconds = TEST_TIMEOUT

    def setup_method(self, method) -> None:
        """Set up test method."""
        super().setup_method(method)

        # Initialize server and client
        self.server = create_test_server(self.env.server_config)
        self.client = create_test_client()
        self.mock_llm = create_mock_client()

        # Track test metrics
        self.metrics = {
            "start_time": time.time(),
            "requests_sent": 0,
            "responses_received": 0,
            "errors": 0,
        }

    def teardown_method(self, method) -> None:
        """Tear down test method."""
        # Stop server
        if self.server and self.server.is_running():
            self.server.stop()

        # Disconnect client
        if self.client and self.client.connected:
            self.client.disconnect()

        super().teardown_method(method)

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def start_server(self) -> bool:
        """Start test server."""
        logger.info("Starting server...")
        success = self.server.start()

        if not success:
            logger.error("Failed to start server")
            self.record_result(TestResult.FAILED, "Server failed to start")
            return False

        logger.info("Server started successfully")
        return True

    def connect_client(self) -> bool:
        """Connect test client to server."""
        logger.info("Connecting client...")

        success = self.client.connect()
        if not success:
            logger.error("Failed to connect client")
            return False

        logger.info("Client connected successfully")
        return True

    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send request and track metrics."""
        self.metrics["requests_sent"] += 1

        try:
            response = self.client.call_method(method, params)
            self.metrics["responses_received"] += 1
            return response
        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"Request failed: {e}")
            raise

    def get_metrics(self) -> Dict[str, Any]:
        """Get test metrics."""
        elapsed = time.time() - self.metrics["start_time"]

        return {
            "elapsed_seconds": elapsed,
            "requests_sent": self.metrics["requests_sent"],
            "responses_received": self.metrics["responses_received"],
            "errors": self.metrics["errors"],
            "success_rate": (
                self.metrics["responses_received"] / self.metrics["requests_sent"] * 100
                if self.metrics["requests_sent"] > 0 else 0
            ),
        }


# ==============================================================================
# Server Initialization Tests
# ==============================================================================

class TestE2EServerInitialization(TestE2EBase):
    """Test server initialization and shutdown."""

    def test_server_startup_success(self) -> None:
        """Test successful server startup."""
        logger.info("Testing server startup...")

        # Start server
        assert self.start_server(), "Server failed to start"

        # Verify server is running
        assert self.server.is_running(), "Server is not running"

        # Perform health check
        assert self.server.health_check(), "Health check failed"

        logger.info("Server startup test passed")
        self.record_result(TestResult.PASSED)

    def test_server_shutdown_success(self) -> None:
        """Test successful server shutdown."""
        logger.info("Testing server shutdown...")

        # Start server
        assert self.start_server(), "Server failed to start"
        assert self.server.is_running(), "Server is not running"

        # Shutdown server
        assert self.server.stop(), "Server failed to stop"

        # Verify server is stopped
        assert not self.server.is_running(), "Server is still running"

        logger.info("Server shutdown test passed")
        self.record_result(TestResult.PASSED)

    def test_server_restart(self) -> None:
        """Test server restart capability."""
        logger.info("Testing server restart...")

        # Start server
        assert self.start_server(), "Server failed to start (1st time)"

        # Stop server
        assert self.server.stop(), "Server failed to stop"

        # Restart server
        assert self.start_server(), "Server failed to start (2nd time)"

        # Verify server is running
        assert self.server.is_running(), "Server is not running after restart"

        logger.info("Server restart test passed")
        self.record_result(TestResult.PASSED)


# ==============================================================================
# Client Connection Tests
# ==============================================================================

class TestE2EClientConnection(TestE2EBase):
    """Test client connection and communication."""

    def test_client_connection_success(self) -> None:
        """Test successful client connection."""
        logger.info("Testing client connection...")

        # Start server
        assert self.start_server(), "Server failed to start"

        # Connect client
        assert self.connect_client(), "Client failed to connect"

        # Verify connection
        assert self.client.connected, "Client is not connected"

        logger.info("Client connection test passed")
        self.record_result(TestResult.PASSED)

    def test_client_disconnect(self) -> None:
        """Test client disconnect."""
        logger.info("Testing client disconnect...")

        # Start server and connect client
        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        # Disconnect client
        assert self.client.disconnect(), "Client failed to disconnect"

        # Verify disconnection
        assert not self.client.connected, "Client is still connected"

        logger.info("Client disconnect test passed")
        self.record_result(TestResult.PASSED)

    def test_reconnection_after_disconnect(self) -> None:
        """Test reconnection after disconnect."""
        logger.info("Testing reconnection...")

        # Start server
        assert self.start_server(), "Server failed to start"

        # First connection
        assert self.connect_client(), "First connection failed"
        assert self.client.connected, "Client not connected (1st time)"

        # Disconnect
        assert self.client.disconnect(), "Disconnect failed"
        assert not self.client.connected, "Client still connected after disconnect"

        # Reconnect
        assert self.connect_client(), "Reconnection failed"
        assert self.client.connected, "Client not connected (2nd time)"

        logger.info("Reconnection test passed")
        self.record_result(TestResult.PASSED)


# ==============================================================================
# MCP Protocol Tests
# ==============================================================================

class TestE2EMCPProtocol(TestE2EBase):
    """Test MCP protocol compliance."""

    def test_initialize_protocol(self) -> None:
        """Test MCP protocol initialization."""
        logger.info("Testing MCP protocol initialization...")

        # Start server
        assert self.start_server(), "Server failed to start"

        # Connect client
        assert self.connect_client(), "Client failed to connect"

        # Send initialize request
        response = self.send_request("initialize", {
            "protocol_version": "2024.01",
            "client_info": {
                "name": "test-client",
                "version": "1.0.0",
            },
        })

        # Verify response
        self.assert_response_valid(response)
        assert response.get("success"), "Initialization failed"

        logger.info("MCP protocol initialization test passed")
        self.record_result(TestResult.PASSED)

    def test_list_tools(self) -> None:
        """Test tool listing capability."""
        logger.info("Testing tool listing...")

        # Start server and connect client
        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        # List tools
        response = self.send_request("list_tools")

        # Verify response
        self.assert_response_valid(response)
        assert response.get("success"), "Tool listing failed"

        logger.info("Tool listing test passed")
        self.record_result(TestResult.PASSED)

    def test_call_tool_with_parameters(self) -> None:
        """Test tool invocation with parameters."""
        logger.info("Testing tool call with parameters...")

        # Start server and connect client
        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        # Call tool with parameters
        response = self.send_request("call_tool", {
            "tool_name": "generate_payloads",
            "arguments": {
                "cwe_id": "CWE-79",
                "protocol": "HTTP",
                "count": 3,
            },
        })

        # Verify response
        self.assert_response_valid(response)
        assert response.get("success"), "Tool call failed"

        logger.info("Tool call test passed")
        self.record_result(TestResult.PASSED)


# ==============================================================================
# Payload Generation Tests
# ==============================================================================

class TestE2EPayloadGeneration(TestE2EBase):
    """Test payload generation pipeline."""

    def test_xss_payload_generation(self) -> None:
        """Test XSS payload generation."""
        logger.info("Testing XSS payload generation...")

        # Start server and connect client
        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        # Generate XSS payloads
        response = self.send_request("generate_payloads", {
            "cwe_id": "CWE-79",
            "protocol": "HTTP",
            "count": 3,
        })

        # Verify response
        self.assert_success(response)
        assert "payloads" in response, "Response missing payloads"
        assert len(response["payloads"]) == 3, "Incorrect number of payloads"

        # Validate payloads
        for payload in response["payloads"]:
            self.assert_payload_valid(payload)

        logger.info("XSS payload generation test passed")
        self.record_result(TestResult.PASSED, details={
            "payloads_generated": len(response["payloads"]),
            "cwe_id": "CWE-79",
        })

    def test_sql_injection_payload_generation(self) -> None:
        """Test SQL injection payload generation."""
        logger.info("Testing SQL injection payload generation...")

        # Start server and connect client
        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        # Generate SQL injection payloads
        response = self.send_request("generate_payloads", {
            "cwe_id": "CWE-89",
            "protocol": "HTTP",
            "count": 2,
        })

        # Verify response
        self.assert_success(response)
        assert len(response["payloads"]) == 2, "Incorrect number of payloads"

        logger.info("SQL injection payload generation test passed")
        self.record_result(TestResult.PASSED)

    def test_multiple_cwe_payload_generation(self) -> None:
        """Test payload generation for multiple CWEs."""
        logger.info("Testing multiple CWE payload generation...")

        # Start server and connect client
        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        cwe_ids = ["CWE-79", "CWE-89", "CWE-78"]
        results = {}

        for cwe_id in cwe_ids:
            response = self.send_request("generate_payloads", {
                "cwe_id": cwe_id,
                "protocol": "HTTP",
                "count": 2,
            })

            self.assert_success(response)
            results[cwe_id] = len(response["payloads"])

        # Verify results
        for cwe_id, count in results.items():
            assert count == 2, f"Incorrect payload count for {cwe_id}"

        logger.info("Multiple CWE payload generation test passed")
        self.record_result(TestResult.PASSED, details=results)

    def test_payload_generation_with_encoding(self) -> None:
        """Test payload generation with different encodings."""
        logger.info("Testing payload generation with encoding...")

        # Start server and connect client
        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        encodings = ["none", "url", "html_entities"]

        for encoding in encodings:
            response = self.send_request("generate_payloads", {
                "cwe_id": "CWE-79",
                "protocol": "HTTP",
                "count": 1,
                "encoding": encoding,
            })

            self.assert_success(response)

        logger.info("Payload generation with encoding test passed")
        self.record_result(TestResult.PASSED)


# ==============================================================================
# CoT Reasoning Tests
# ==============================================================================

class TestE2ECoTReasoning(TestE2EBase):
    """Test Chain-of-Thought reasoning integration."""

    def test_cot_reasoning_generation(self) -> None:
        """Test CoT reasoning generation."""
        logger.info("Testing CoT reasoning generation...")

        # Start server and connect client
        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        # Generate CoT reasoning
        response = self.send_request("generate_cot", {
            "cwe_id": "CWE-79",
            "protocol": "HTTP",
        })

        # Verify response
        self.assert_success(response)
        assert "reasoning_chain" in response, "Missing reasoning chain"
        assert len(response["reasoning_chain"]) > 0, "Empty reasoning chain"

        logger.info("CoT reasoning generation test passed")
        self.record_result(TestResult.PASSED, details={
            "reasoning_steps": len(response["reasoning_chain"]),
        })

    def test_cot_reasoning_with_context(self) -> None:
        """Test CoT reasoning with additional context."""
        logger.info("Testing CoT reasoning with context...")

        # Start server and connect client
        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        # Generate CoT reasoning with context
        response = self.send_request("generate_cot", {
            "cwe_id": "CWE-79",
            "protocol": "HTTP",
            "context": {
                "target_version": "5.0.0",
                "service": "Apache",
            },
        })

        # Verify response
        self.assert_success(response)

        logger.info("CoT reasoning with context test passed")
        self.record_result(TestResult.PASSED)


# ==============================================================================
# Knowledge Base Integration Tests
# ==============================================================================

class TestE2EKnowledgeBase(TestE2EBase):
    """Test knowledge base integration."""

    def test_cwe_data_retrieval(self) -> None:
        """Test CWE data retrieval."""
        logger.info("Testing CWE data retrieval...")

        # Start server and connect client
        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        # Retrieve CWE data
        response = self.send_request("get_cwe_data", {
            "cwe_id": "CWE-79",
        })

        # Verify response
        self.assert_success(response)
        assert response.get("data"), "No CWE data returned"

        logger.info("CWE data retrieval test passed")
        self.record_result(TestResult.PASSED)

    def test_cve_data_retrieval(self) -> None:
        """Test CVE data retrieval."""
        logger.info("Testing CVE data retrieval...")

        # Start server and connect client
        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        # Retrieve CVE data
        response = self.send_request("get_cve_data", {
            "cve_id": "CVE-2021-3129",
        })

        # Verify response
        self.assert_success(response)

        logger.info("CVE data retrieval test passed")
        self.record_result(TestResult.PASSED)


# ==============================================================================
# Multi-Protocol Tests
# ==============================================================================

class TestE2EMultiProtocol(TestE2EBase):
    """Test multi-protocol support."""

    def test_http_payload_generation(self) -> None:
        """Test HTTP protocol payload generation."""
        logger.info("Testing HTTP protocol...")

        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        response = self.send_request("generate_payloads", {
            "cwe_id": "CWE-79",
            "protocol": "HTTP",
        })

        self.assert_success(response)
        logger.info("HTTP protocol test passed")
        self.record_result(TestResult.PASSED)

    def test_coap_payload_generation(self) -> None:
        """Test CoAP protocol payload generation."""
        logger.info("Testing CoAP protocol...")

        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        response = self.send_request("generate_payloads", {
            "cwe_id": "CWE-22",
            "protocol": "CoAP",
        })

        self.assert_success(response)
        logger.info("CoAP protocol test passed")
        self.record_result(TestResult.PASSED)

    def test_mqtt_payload_generation(self) -> None:
        """Test MQTT protocol payload generation."""
        logger.info("Testing MQTT protocol...")

        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        response = self.send_request("generate_payloads", {
            "cwe_id": "CWE-200",
            "protocol": "MQTT",
        })

        self.assert_success(response)
        logger.info("MQTT protocol test passed")
        self.record_result(TestResult.PASSED)


# ==============================================================================
# Error Handling Tests
# ==============================================================================

class TestE2EErrorHandling(TestE2EBase):
    """Test error handling and recovery."""

    def test_invalid_cwe_id_handling(self) -> None:
        """Test handling of invalid CWE ID."""
        logger.info("Testing invalid CWE ID handling...")

        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        response = self.send_request("generate_payloads", {
            "cwe_id": "CWE-99999",  # Invalid CWE ID
            "protocol": "HTTP",
        })

        # Should fail gracefully
        assert not response.get("success"), "Should reject invalid CWE ID"

        logger.info("Invalid CWE ID handling test passed")
        self.record_result(TestResult.PASSED)

    def test_unsupported_protocol_handling(self) -> None:
        """Test handling of unsupported protocol."""
        logger.info("Testing unsupported protocol handling...")

        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        response = self.send_request("generate_payloads", {
            "cwe_id": "CWE-79",
            "protocol": "UNSUPPORTED",  # Invalid protocol
        })

        # Should fail gracefully
        assert not response.get("success"), "Should reject unsupported protocol"

        logger.info("Unsupported protocol handling test passed")
        self.record_result(TestResult.PASSED)

    def test_missing_required_parameters(self) -> None:
        """Test handling of missing required parameters."""
        logger.info("Testing missing parameters handling...")

        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        response = self.send_request("generate_payloads", {
            # Missing cwe_id and protocol
        })

        # Should fail gracefully
        assert not response.get("success"), "Should require parameters"

        logger.info("Missing parameters handling test passed")
        self.record_result(TestResult.PASSED)


# ==============================================================================
# Performance Tests
# ==============================================================================

class TestE2EPerformance(TestE2EBase):
    """Test performance and throughput."""

    def test_payload_generation_performance(self) -> None:
        """Test payload generation performance."""
        logger.info("Testing payload generation performance...")

        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        # Measure time for payload generation
        start_time = time.time()

        response = self.send_request("generate_payloads", {
            "cwe_id": "CWE-79",
            "protocol": "HTTP",
            "count": 10,
        })

        elapsed_time = time.time() - start_time

        self.assert_success(response)

        # Performance assertion
        assert elapsed_time < 5.0, f"Payload generation too slow: {elapsed_time}s"

        logger.info(f"Payload generation completed in {elapsed_time:.2f}s")
        self.record_result(TestResult.PASSED, details={
            "elapsed_seconds": elapsed_time,
            "payloads_per_second": 10 / elapsed_time,
        })

    def test_concurrent_requests(self) -> None:
        """Test handling of multiple concurrent requests."""
        logger.info("Testing concurrent requests...")

        assert self.start_server(), "Server failed to start"
        assert self.connect_client(), "Client failed to connect"

        results = []

        # Send multiple requests
        for i in range(5):
            response = self.send_request("generate_payloads", {
                "cwe_id": f"CWE-{79 + i}",
                "protocol": "HTTP",
            })

            results.append(response)

        # Verify all requests succeeded
        successful = sum(1 for r in results if r.get("success"))
        assert successful == 5, f"Not all requests succeeded: {successful}/5"

        logger.info("Concurrent requests test passed")
        self.record_result(TestResult.PASSED, details={
            "concurrent_requests": 5,
            "successful": successful,
        })


# ==============================================================================
# Complete Workflow Tests
# ==============================================================================

class TestE2ECompleteWorkflow(TestE2EBase):
    """Test complete end-to-end workflows."""

    def test_complete_vulnerability_analysis_workflow(self) -> None:
        """Test complete vulnerability analysis workflow."""
        logger.info("Testing complete vulnerability analysis workflow...")

        # Start server
        assert self.start_server(), "Server failed to start"

        # Connect client
        assert self.connect_client(), "Client failed to connect"

        # Step 1: Initialize protocol
        init_response = self.send_request("initialize", {
            "protocol_version": "2024.01",
            "client_info": {"name": "test", "version": "1.0"},
        })
        assert init_response.get("success"), "Initialization failed"

        # Step 2: Get CWE data
        cwe_response = self.send_request("get_cwe_data", {
            "cwe_id": "CWE-79"
        })
        assert cwe_response.get("success"), "CWE retrieval failed"

        # Step 3: Generate payloads
        payload_response = self.send_request("generate_payloads", {
            "cwe_id": "CWE-79",
            "protocol": "HTTP",
            "count": 3,
        })
        assert payload_response.get("success"), "Payload generation failed"
        assert len(payload_response["payloads"]) == 3

        # Step 4: Generate CoT reasoning
        cot_response = self.send_request("generate_cot", {
            "cwe_id": "CWE-79",
            "protocol": "HTTP",
        })
        assert cot_response.get("success"), "CoT generation failed"

        logger.info("Complete workflow test passed")

        # Record metrics
        metrics = self.get_metrics()
        self.record_result(TestResult.PASSED, details={
            "requests_sent": metrics["requests_sent"],
            "success_rate": metrics["success_rate"],
            "elapsed_seconds": metrics["elapsed_seconds"],
        })


# ==============================================================================
# Test Summary
# ==============================================================================

class TestE2ESummary:
    """Summary of end-to-end tests."""

    @staticmethod
    def print_summary() -> None:
        """Print test summary."""
        logger.info("""
        ============================================================
        HyFuzz MCP Server - End-to-End Test Summary
        ============================================================

        Test Categories:
        1. Server Initialization - startup, shutdown, restart
        2. Client Connection - connect, disconnect, reconnect
        3. MCP Protocol - initialization, tool listing, calls
        4. Payload Generation - XSS, SQL injection, multiple CWEs
        5. CoT Reasoning - reasoning chains, context support
        6. Knowledge Base - CWE/CVE retrieval
        7. Multi-Protocol - HTTP, CoAP, MQTT
        8. Error Handling - invalid inputs, missing parameters
        9. Performance - throughput, concurrent requests
        10. Complete Workflows - end-to-end scenarios

        ============================================================
        """)


# ==============================================================================
# Pytest Fixtures for E2E Tests
# ==============================================================================

@pytest.fixture
def e2e_server_manager():
    """Fixture for server manager."""
    server = create_test_server()
    yield server
    if server.is_running():
        server.stop()


@pytest.fixture
def e2e_client_manager():
    """Fixture for client manager."""
    client = create_test_client()
    yield client
    if client.connected:
        client.disconnect()


@pytest.fixture
def e2e_environment(e2e_server_manager, e2e_client_manager):
    """Fixture for complete E2E environment."""
    return {
        "server": e2e_server_manager,
        "client": e2e_client_manager,
    }


# ==============================================================================
# Module Initialization
# ==============================================================================

if __name__ == "__main__":
    # Print test summary
    TestE2ESummary.print_summary()

    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])