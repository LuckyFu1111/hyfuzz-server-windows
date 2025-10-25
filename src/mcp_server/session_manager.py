"""
HyFuzz MCP Server - Session Manager

This module implements session management for the MCP server, handling the complete
lifecycle of client sessions including creation, validation, state management, and cleanup.

Key Features:
- Session lifecycle management (creation, suspension, resumption, termination)
- Concurrent session handling with thread-safe operations
- Session authentication and API key validation
- Session timeout and automatic cleanup
- Session state transitions with validation
- Context preservation across requests
- Request history tracking
- Capability negotiation tracking
- Session metrics and statistics
- Optional persistent storage
- Resource cleanup and garbage collection

Session States:
- INITIALIZED: Session created but not yet fully initialized
- ACTIVE: Session is fully active and processing requests
- SUSPENDED: Session temporarily suspended (can be resumed)
- CLOSING: Session is being closed gracefully
- CLOSED: Session is fully closed and cleaned up

Author: HyFuzz Team
Version: 1.0.0
"""

import asyncio
import logging
import time
import uuid
import json
from typing import Dict, Any, Optional, List, Tuple, Callable
from enum import Enum
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta, timezone
from collections import OrderedDict
import threading


# ============================================================================
# Constants and Enumerations
# ============================================================================

class SessionState(Enum):
    """Session state enumerations"""
    INITIALIZED = "initialized"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSING = "closing"
    CLOSED = "closed"


class SessionEventType(Enum):
    """Session event types for audit trail"""
    CREATED = "created"
    ACTIVATED = "activated"
    SUSPENDED = "suspended"
    RESUMED = "resumed"
    CLOSED = "closed"
    ERROR = "error"
    CLEANUP = "cleanup"


# State transition rules
VALID_STATE_TRANSITIONS = {
    SessionState.INITIALIZED: [SessionState.ACTIVE, SessionState.CLOSED],
    SessionState.ACTIVE: [SessionState.SUSPENDED, SessionState.CLOSING, SessionState.CLOSED],
    SessionState.SUSPENDED: [SessionState.ACTIVE, SessionState.CLOSED],
    SessionState.CLOSING: [SessionState.CLOSED],
    SessionState.CLOSED: [],
}

# Default configuration constants
DEFAULT_SESSION_TIMEOUT = 3600  # 1 hour in seconds
DEFAULT_MAX_SESSIONS = 500
DEFAULT_REQUEST_HISTORY_SIZE = 100
DEFAULT_CLEANUP_INTERVAL = 300  # 5 minutes


# ============================================================================
# Logger Setup
# ============================================================================

def get_logger(name: str) -> logging.Logger:
    """Get or create logger"""
    return logging.getLogger(name)


logger = get_logger(__name__)


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class ClientInfo:
    """Client information"""
    name: str
    version: str
    user_agent: Optional[str] = None
    platform: Optional[str] = None
    extra_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "version": self.version,
            "user_agent": self.user_agent,
            "platform": self.platform,
            "extra_info": self.extra_info,
        }


@dataclass
class SessionEvent:
    """Session event audit trail entry"""
    timestamp: datetime
    event_type: SessionEventType
    details: Optional[str] = None
    request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "details": self.details,
            "request_id": self.request_id,
        }


@dataclass
class RequestRecord:
    """Record of a single request in session history"""
    request_id: str
    method: str
    timestamp: datetime
    duration_ms: float
    status: str  # "success" or "error"
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "request_id": self.request_id,
            "method": self.method,
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
            "status": self.status,
            "error_message": self.error_message,
        }


@dataclass
class SessionStats:
    """Session statistics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_request_time_ms: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def avg_request_time_ms(self) -> float:
        """Calculate average request time"""
        if self.total_requests == 0:
            return 0.0
        return self.total_request_time_ms / self.total_requests

    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100

    @property
    def duration_seconds(self) -> float:
        """Get total session duration in seconds"""
        return (datetime.now(timezone.utc) - self.created_at).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "avg_request_time_ms": self.avg_request_time_ms,
            "success_rate_percent": self.success_rate,
            "duration_seconds": self.duration_seconds,
            "created_at": self.created_at.isoformat(),
            "last_activity_time": self.last_activity_time.isoformat(),
        }


@dataclass
class Session:
    """Represents a client session"""
    session_id: str
    client_info: ClientInfo
    created_at: datetime
    last_activity: datetime
    state: SessionState = SessionState.INITIALIZED

    # Authentication and security
    api_key: Optional[str] = None
    authenticated: bool = False

    # Context
    context: Dict[str, Any] = field(default_factory=dict)
    capabilities_negotiated: Dict[str, Any] = field(default_factory=dict)

    # History and tracking
    request_history: List[RequestRecord] = field(default_factory=list)
    events: List[SessionEvent] = field(default_factory=list)
    stats: SessionStats = field(default_factory=SessionStats)

    # Metadata
    timeout_seconds: int = DEFAULT_SESSION_TIMEOUT
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Internal state
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _cleanup_scheduled: bool = False

    def to_dict(self, include_history: bool = True) -> Dict[str, Any]:
        """Convert session to dictionary"""
        session_dict = {
            "session_id": self.session_id,
            "client_info": self.client_info.to_dict(),
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "state": self.state.value,
            "authenticated": self.authenticated,
            "context": self.context,
            "capabilities_negotiated": self.capabilities_negotiated,
            "stats": self.stats.to_dict(),
            "timeout_seconds": self.timeout_seconds,
            "metadata": self.metadata,
        }

        if include_history:
            session_dict["request_history"] = [
                record.to_dict() for record in self.request_history
            ]
            session_dict["events"] = [
                event.to_dict() for event in self.events
            ]

        return session_dict

    def is_expired(self) -> bool:
        """Check if session has expired"""
        elapsed = (datetime.now(timezone.utc) - self.last_activity).total_seconds()
        return elapsed > self.timeout_seconds

    def is_active(self) -> bool:
        """Check if session is active"""
        return self.state == SessionState.ACTIVE and not self.is_expired()


# ============================================================================
# Session Manager Class
# ============================================================================

class SessionManager:
    """
    Manages MCP client sessions with full lifecycle support.

    Features:
    - Session creation and deletion
    - Concurrent session tracking
    - Authentication validation
    - State management and transitions
    - Automatic timeout and cleanup
    - Session metrics and statistics
    - Request history tracking
    """

    def __init__(
            self,
            max_sessions: int = DEFAULT_MAX_SESSIONS,
            session_timeout: int = DEFAULT_SESSION_TIMEOUT,
            cleanup_interval: int = DEFAULT_CLEANUP_INTERVAL,
            api_keys: Optional[List[str]] = None,
    ):
        """
        Initialize session manager

        Args:
            max_sessions: Maximum concurrent sessions allowed
            session_timeout: Default session timeout in seconds
            cleanup_interval: Interval for cleanup task in seconds
            api_keys: List of valid API keys (None = auth disabled)
        """
        self.max_sessions = max_sessions
        self.session_timeout = session_timeout
        self.cleanup_interval = cleanup_interval
        self.api_keys = set(api_keys) if api_keys else None

        # Session storage
        self.sessions: Dict[str, Session] = {}
        self.sessions_lock = asyncio.Lock()

        # Statistics
        self.total_sessions_created = 0
        self.cleanup_task: Optional[asyncio.Task] = None

        logger.info(
            f"SessionManager initialized: "
            f"max={max_sessions}, timeout={session_timeout}s, "
            f"auth_enabled={self.api_keys is not None}"
        )

    async def create_session(
            self,
            client_info: ClientInfo,
            api_key: Optional[str] = None,
            context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a new session

        Args:
            client_info: Client information
            api_key: Optional API key for authentication
            context: Optional initial context

        Returns:
            Session ID

        Raises:
            RuntimeError: If max sessions reached or auth fails
        """
        async with self.sessions_lock:
            # Check session limit
            if len(self.sessions) >= self.max_sessions:
                logger.warning(
                    f"Session limit reached ({self.max_sessions}), "
                    f"rejecting new session from {client_info.name}"
                )
                raise RuntimeError(
                    f"Maximum sessions ({self.max_sessions}) reached"
                )

            # Validate API key if authentication is enabled
            if self.api_keys is not None and api_key not in self.api_keys:
                logger.warning(
                    f"Invalid API key for session from {client_info.name}"
                )
                raise RuntimeError("Invalid API key")

            # Generate session ID
            session_id = str(uuid.uuid4())

            # Create session
            now = datetime.now(timezone.utc)
            session = Session(
                session_id=session_id,
                client_info=client_info,
                created_at=now,
                last_activity=now,
                api_key=api_key,
                authenticated=True if api_key else False,
                context=context or {},
                timeout_seconds=self.session_timeout,
            )

            # Record creation event
            session.events.append(
                SessionEvent(
                    timestamp=now,
                    event_type=SessionEventType.CREATED,
                    details=f"Session created for {client_info.name} v{client_info.version}",
                )
            )

            # Store session
            self.sessions[session_id] = session
            self.total_sessions_created += 1

            logger.info(
                f"Session created: {session_id} "
                f"({client_info.name} v{client_info.version})"
            )

            # Schedule cleanup task if not already running
            if self.cleanup_task is None or self.cleanup_task.done():
                self.cleanup_task = asyncio.create_task(self._cleanup_loop())

            return session_id

    async def activate_session(self, session_id: str) -> None:
        """
        Activate a session (transition from INITIALIZED to ACTIVE)

        Args:
            session_id: Session ID

        Raises:
            ValueError: If session not found or invalid state transition
        """
        async with self.sessions_lock:
            session = self._get_session_unsafe(session_id)

            if session is None:
                raise ValueError(f"Session not found: {session_id}")

            await self._transition_state_unsafe(
                session,
                SessionState.ACTIVE,
                f"Session activated",
            )

    async def get_session(self, session_id: str) -> Optional[Session]:
        """
        Get session by ID

        Args:
            session_id: Session ID

        Returns:
            Session object or None if not found
        """
        async with self.sessions_lock:
            session = self._get_session_unsafe(session_id)
            return session

    async def close_session(self, session_id: str) -> None:
        """
        Close a session gracefully

        Args:
            session_id: Session ID
        """
        async with self.sessions_lock:
            session = self._get_session_unsafe(session_id)

            if session is None:
                logger.debug(f"Cannot close: session not found {session_id}")
                return

            # Transition to CLOSED state
            await self._transition_state_unsafe(
                session,
                SessionState.CLOSED,
                "Session closed by user",
            )

    async def suspend_session(self, session_id: str) -> None:
        """
        Suspend a session temporarily

        Args:
            session_id: Session ID
        """
        async with self.sessions_lock:
            session = self._get_session_unsafe(session_id)

            if session is None:
                raise ValueError(f"Session not found: {session_id}")

            await self._transition_state_unsafe(
                session,
                SessionState.SUSPENDED,
                "Session suspended",
            )

    async def resume_session(self, session_id: str) -> None:
        """
        Resume a suspended session

        Args:
            session_id: Session ID
        """
        async with self.sessions_lock:
            session = self._get_session_unsafe(session_id)

            if session is None:
                raise ValueError(f"Session not found: {session_id}")

            await self._transition_state_unsafe(
                session,
                SessionState.ACTIVE,
                "Session resumed",
            )

    async def record_request(
            self,
            session_id: str,
            request_id: str,
            method: str,
            duration_ms: float,
            status: str,
            error_message: Optional[str] = None,
    ) -> None:
        """
        Record a request in session history

        Args:
            session_id: Session ID
            request_id: Request ID
            method: RPC method name
            duration_ms: Request duration in milliseconds
            status: "success" or "error"
            error_message: Error message if failed
        """
        async with self.sessions_lock:
            session = self._get_session_unsafe(session_id)

            if session is None:
                logger.debug(f"Cannot record request: session not found {session_id}")
                return

            # Create request record
            record = RequestRecord(
                request_id=request_id,
                method=method,
                timestamp=datetime.now(timezone.utc),
                duration_ms=duration_ms,
                status=status,
                error_message=error_message,
            )

            # Add to history (maintain max size)
            session.request_history.append(record)
            if len(session.request_history) > DEFAULT_REQUEST_HISTORY_SIZE:
                session.request_history = session.request_history[-DEFAULT_REQUEST_HISTORY_SIZE:]

            # Update stats
            session.stats.total_requests += 1
            session.stats.total_request_time_ms += duration_ms
            session.stats.last_activity_time = datetime.now(timezone.utc)
            session.last_activity = datetime.now(timezone.utc)

            if status == "success":
                session.stats.successful_requests += 1
            else:
                session.stats.failed_requests += 1

    async def update_context(
            self,
            session_id: str,
            context_updates: Dict[str, Any],
    ) -> None:
        """
        Update session context

        Args:
            session_id: Session ID
            context_updates: Context updates to merge
        """
        async with self.sessions_lock:
            session = self._get_session_unsafe(session_id)

            if session is None:
                logger.debug(f"Cannot update context: session not found {session_id}")
                return

            session.context.update(context_updates)
            session.last_activity = datetime.now(timezone.utc)

    async def update_capabilities(
            self,
            session_id: str,
            capabilities: Dict[str, Any],
    ) -> None:
        """
        Update negotiated capabilities for session

        Args:
            session_id: Session ID
            capabilities: Negotiated capabilities
        """
        async with self.sessions_lock:
            session = self._get_session_unsafe(session_id)

            if session is None:
                logger.debug(f"Cannot update capabilities: session not found {session_id}")
                return

            session.capabilities_negotiated = capabilities
            session.last_activity = datetime.now(timezone.utc)

    async def get_active_sessions(self) -> List[str]:
        """Get list of active session IDs"""
        async with self.sessions_lock:
            return [
                sid for sid, session in self.sessions.items()
                if session.is_active()
            ]

    async def get_active_count(self) -> int:
        """Get count of active sessions"""
        return len(await self.get_active_sessions())

    async def get_all_sessions(self, include_closed: bool = False) -> List[Session]:
        """
        Get all sessions

        Args:
            include_closed: Whether to include closed sessions

        Returns:
            List of sessions
        """
        async with self.sessions_lock:
            sessions = list(self.sessions.values())
            if not include_closed:
                sessions = [s for s in sessions if s.state != SessionState.CLOSED]
            return sessions

    async def get_session_stats(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session statistics"""
        session = await self.get_session(session_id)
        if session:
            return session.stats.to_dict()
        return None

    # ========================================================================
    # Internal Helper Methods
    # ========================================================================

    def _get_session_unsafe(self, session_id: str) -> Optional[Session]:
        """
        Get session without locking (must be called with lock held)

        Args:
            session_id: Session ID

        Returns:
            Session or None
        """
        return self.sessions.get(session_id)

    async def _transition_state_unsafe(
            self,
            session: Session,
            new_state: SessionState,
            reason: str,
    ) -> None:
        """
        Transition session state with validation (must be called with lock held)

        Args:
            session: Session object
            new_state: New state to transition to
            reason: Reason for state transition

        Raises:
            ValueError: If invalid state transition
        """
        current_state = session.state

        # Validate state transition
        if new_state not in VALID_STATE_TRANSITIONS.get(current_state, []):
            raise ValueError(
                f"Invalid state transition: {current_state.value} -> {new_state.value}"
            )

        # Transition state
        session.state = new_state
        session.last_activity = datetime.now(timezone.utc)

        # Record event
        event_type_map = {
            SessionState.ACTIVE: SessionEventType.ACTIVATED,
            SessionState.SUSPENDED: SessionEventType.SUSPENDED,
            SessionState.CLOSED: SessionEventType.CLOSED,
        }

        event_type = event_type_map.get(new_state, SessionEventType.CREATED)
        session.events.append(
            SessionEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                details=reason,
            )
        )

        logger.debug(f"Session {session.session_id} transitioned to {new_state.value}: {reason}")

    async def _cleanup_loop(self) -> None:
        """Background cleanup task for expired sessions"""
        logger.debug("Session cleanup loop started")

        try:
            while True:
                await asyncio.sleep(self.cleanup_interval)

                async with self.sessions_lock:
                    expired_sessions = []

                    for session_id, session in self.sessions.items():
                        # Check for expired sessions
                        if session.state == SessionState.ACTIVE and session.is_expired():
                            logger.info(
                                f"Session {session_id} expired "
                                f"({session.stats.duration_seconds:.0f}s active)"
                            )
                            expired_sessions.append(session_id)

                        # Check for CLOSED sessions older than 1 hour (can be removed)
                        elif session.state == SessionState.CLOSED:
                            if (datetime.now(timezone.utc) - session.last_activity).total_seconds() > 3600:
                                expired_sessions.append(session_id)

                    # Remove expired sessions
                    for session_id in expired_sessions:
                        session = self.sessions.pop(session_id, None)
                        if session:
                            session.events.append(
                                SessionEvent(
                                    timestamp=datetime.now(timezone.utc),
                                    event_type=SessionEventType.CLEANUP,
                                    details="Session removed during cleanup",
                                )
                            )
                            logger.debug(f"Cleaned up session: {session_id}")

        except asyncio.CancelledError:
            logger.debug("Session cleanup loop cancelled")
        except Exception as ex:
            logger.error(f"Error in session cleanup loop: {str(ex)}", exc_info=True)

    def get_stats(self) -> Dict[str, Any]:
        """Get session manager statistics"""
        return {
            "total_sessions_created": self.total_sessions_created,
            "active_sessions": len([s for s in self.sessions.values() if s.is_active()]),
            "total_sessions": len(self.sessions),
            "max_sessions": self.max_sessions,
            "sessions_by_state": {
                state.value: len([s for s in self.sessions.values() if s.state == state])
                for state in SessionState
            }
        }


# ============================================================================
# Test Suite
# ============================================================================

async def run_tests():
    """Run session manager tests"""

    print("\n" + "=" * 80)
    print("SESSION MANAGER TEST SUITE")
    print("=" * 80 + "\n")

    # Test 1: Session creation
    print("[TEST 1] Session Creation")
    try:
        manager = SessionManager(max_sessions=10)

        client_info = ClientInfo(
            name="test-client",
            version="1.0.0",
        )

        session_id = await manager.create_session(client_info)
        assert session_id is not None
        assert len(session_id) > 0

        session = await manager.get_session(session_id)
        assert session is not None
        assert session.client_info.name == "test-client"
        assert session.state == SessionState.INITIALIZED

        print("✓ Session creation test passed\n")
    except Exception as e:
        print(f"✗ Session creation test failed: {str(e)}\n")
        return

    # Test 2: Session activation
    print("[TEST 2] Session Activation")
    try:
        manager = SessionManager()
        client_info = ClientInfo(name="test-client", version="1.0.0")
        session_id = await manager.create_session(client_info)

        await manager.activate_session(session_id)
        session = await manager.get_session(session_id)
        assert session.state == SessionState.ACTIVE

        print("✓ Session activation test passed\n")
    except Exception as e:
        print(f"✗ Session activation test failed: {str(e)}\n")
        return

    # Test 3: Session suspension and resumption
    print("[TEST 3] Session Suspension/Resumption")
    try:
        manager = SessionManager()
        client_info = ClientInfo(name="test-client", version="1.0.0")
        session_id = await manager.create_session(client_info)
        await manager.activate_session(session_id)

        # Suspend
        await manager.suspend_session(session_id)
        session = await manager.get_session(session_id)
        assert session.state == SessionState.SUSPENDED

        # Resume
        await manager.resume_session(session_id)
        session = await manager.get_session(session_id)
        assert session.state == SessionState.ACTIVE

        print("✓ Session suspension/resumption test passed\n")
    except Exception as e:
        print(f"✗ Session suspension/resumption test failed: {str(e)}\n")
        return

    # Test 4: Session closure
    print("[TEST 4] Session Closure")
    try:
        manager = SessionManager()
        client_info = ClientInfo(name="test-client", version="1.0.0")
        session_id = await manager.create_session(client_info)

        await manager.close_session(session_id)
        session = await manager.get_session(session_id)
        assert session.state == SessionState.CLOSED

        print("✓ Session closure test passed\n")
    except Exception as e:
        print(f"✗ Session closure test failed: {str(e)}\n")
        return

    # Test 5: Request recording
    print("[TEST 5] Request Recording")
    try:
        manager = SessionManager()
        client_info = ClientInfo(name="test-client", version="1.0.0")
        session_id = await manager.create_session(client_info)

        # Record some requests
        await manager.record_request(session_id, "req-1", "test_method", 10.5, "success")
        await manager.record_request(session_id, "req-2", "test_method", 15.2, "success")
        await manager.record_request(session_id, "req-3", "test_method", 5.0, "error", "Test error")

        session = await manager.get_session(session_id)
        assert session.stats.total_requests == 3
        assert session.stats.successful_requests == 2
        assert session.stats.failed_requests == 1
        assert len(session.request_history) == 3

        print("✓ Request recording test passed\n")
    except Exception as e:
        print(f"✗ Request recording test failed: {str(e)}\n")
        return

    # Test 6: Context management
    print("[TEST 6] Context Management")
    try:
        manager = SessionManager()
        client_info = ClientInfo(name="test-client", version="1.0.0")
        session_id = await manager.create_session(client_info)

        # Update context
        await manager.update_context(session_id, {"key1": "value1", "key2": "value2"})
        session = await manager.get_session(session_id)
        assert session.context["key1"] == "value1"
        assert session.context["key2"] == "value2"

        print("✓ Context management test passed\n")
    except Exception as e:
        print(f"✗ Context management test failed: {str(e)}\n")
        return

    # Test 7: API key authentication
    print("[TEST 7] API Key Authentication")
    try:
        manager = SessionManager(api_keys=["valid-key-123"])
        client_info = ClientInfo(name="test-client", version="1.0.0")

        # Invalid API key
        try:
            await manager.create_session(client_info, api_key="invalid-key")
            assert False, "Should have rejected invalid API key"
        except RuntimeError:
            pass  # Expected

        # Valid API key
        session_id = await manager.create_session(client_info, api_key="valid-key-123")
        session = await manager.get_session(session_id)
        assert session.authenticated is True

        print("✓ API key authentication test passed\n")
    except Exception as e:
        print(f"✗ API key authentication test failed: {str(e)}\n")
        return

    # Test 8: Max sessions limit
    print("[TEST 8] Max Sessions Limit")
    try:
        manager = SessionManager(max_sessions=3)

        # Create 3 sessions (should succeed)
        for i in range(3):
            client_info = ClientInfo(name=f"client-{i}", version="1.0.0")
            await manager.create_session(client_info)

        # Try to create 4th session (should fail)
        try:
            client_info = ClientInfo(name="client-4", version="1.0.0")
            await manager.create_session(client_info)
            assert False, "Should have rejected session due to limit"
        except RuntimeError as e:
            assert "Maximum sessions" in str(e)

        print("✓ Max sessions limit test passed\n")
    except Exception as e:
        print(f"✗ Max sessions limit test failed: {str(e)}\n")
        return

    # Test 9: Session statistics
    print("[TEST 9] Session Statistics")
    try:
        manager = SessionManager()
        client_info = ClientInfo(name="test-client", version="1.0.0")
        session_id = await manager.create_session(client_info)

        # Record requests
        for i in range(5):
            await manager.record_request(session_id, f"req-{i}", "method", 10.0, "success")

        stats = await manager.get_session_stats(session_id)
        assert stats["total_requests"] == 5
        assert stats["successful_requests"] == 5
        assert stats["avg_request_time_ms"] == 10.0
        assert stats["success_rate_percent"] == 100.0

        print("✓ Session statistics test passed\n")
    except Exception as e:
        print(f"✗ Session statistics test failed: {str(e)}\n")
        return

    # Test 10: Session manager statistics
    print("[TEST 10] Session Manager Statistics")
    try:
        manager = SessionManager(max_sessions=10)

        # Create sessions
        for i in range(3):
            client_info = ClientInfo(name=f"client-{i}", version="1.0.0")
            await manager.create_session(client_info)

        stats = manager.get_stats()
        assert stats["total_sessions_created"] == 3
        assert stats["total_sessions"] == 3
        assert stats["max_sessions"] == 10

        print("✓ Session manager statistics test passed\n")
    except Exception as e:
        print(f"✗ Session manager statistics test failed: {str(e)}\n")
        return

    print("=" * 80)
    print("ALL TESTS PASSED! ✓")
    print("=" * 80 + "\n")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    """Run test suite when executed directly"""
    asyncio.run(run_tests())