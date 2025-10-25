"""
Common Models - Shared and Utility Data Models

This module contains shared/utility data models used throughout the HyFuzz
Windows MCP Server for handling requests, responses, pagination, and timestamps.

Models:
    - RequestContext: Encapsulates request metadata and context information
    - ResponseStatus: Enum for response status values (success, error, etc.)
    - ErrorResponse: Structure for error responses with details
    - SuccessResponse: Structure for successful responses with results
    - PagedResponse: Wrapper for paginated results
    - BatchOperation: Structure for batch operation requests
    - Timestamp: Utility class for timestamp handling

Author: HyFuzz Team
Version: 1.0.0
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Generic, TypeVar
from uuid import uuid4, UUID
import json

# ============================================================================
# TYPE VARIABLES
# ============================================================================

T = TypeVar('T')  # Generic type variable for PagedResponse


# ============================================================================
# 1. ResponseStatus ENUM
# ============================================================================

class ResponseStatus(str, Enum):
    """
    Enumeration of possible response status values.

    Attributes:
        SUCCESS: Operation completed successfully
        ERROR: Operation failed with an error
        PENDING: Operation is pending/in progress
        PARTIAL: Partial success (some items failed)
        NOT_FOUND: Resource not found
        TIMEOUT: Operation timed out
        CANCELLED: Operation was cancelled
    """
    SUCCESS = "success"
    ERROR = "error"
    PENDING = "pending"
    PARTIAL = "partial"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

    @classmethod
    def is_success(cls, status: 'ResponseStatus') -> bool:
        """Check if status indicates success."""
        return status in (cls.SUCCESS, cls.PARTIAL)

    @classmethod
    def is_error(cls, status: 'ResponseStatus') -> bool:
        """Check if status indicates error."""
        return status in (cls.ERROR, cls.TIMEOUT, cls.NOT_FOUND)


# ============================================================================
# 2. Timestamp UTILITY CLASS
# ============================================================================

@dataclass
class Timestamp:
    """
    Utility class for handling timestamps with timezone support.

    Attributes:
        value: The datetime value (UTC)
        timezone_name: Timezone information (default: UTC)
    """
    value: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    timezone_name: str = field(default="UTC")

    def __post_init__(self):
        """Ensure value is timezone-aware."""
        if self.value.tzinfo is None:
            self.value = self.value.replace(tzinfo=timezone.utc)

    def iso_format(self) -> str:
        """Return ISO 8601 formatted timestamp."""
        return self.value.isoformat()

    def timestamp_seconds(self) -> float:
        """Return Unix timestamp in seconds."""
        return self.value.timestamp()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "value": self.iso_format(),
            "timezone": self.timezone_name,
            "unix_timestamp": self.timestamp_seconds()
        }

    @staticmethod
    def now() -> 'Timestamp':
        """Create a Timestamp for the current moment."""
        return Timestamp(value=datetime.now(timezone.utc))

    @staticmethod
    def from_iso_string(iso_string: str) -> 'Timestamp':
        """Create Timestamp from ISO 8601 string."""
        dt = datetime.fromisoformat(iso_string)
        return Timestamp(value=dt)


# ============================================================================
# 3. RequestContext DATA MODEL
# ============================================================================

@dataclass
class RequestContext:
    """
    Encapsulates request metadata and context information.

    Used to track request metadata, user context, and operation details
    throughout the application lifecycle.

    Attributes:
        request_id: Unique identifier for the request (auto-generated)
        user_id: Optional identifier for the requesting user
        session_id: Optional session identifier
        timestamp: Request creation timestamp
        source: Source of the request (e.g., 'mcp', 'api', 'cli')
        version: API/protocol version
        metadata: Additional custom metadata as key-value pairs
    """
    request_id: str = field(default_factory=lambda: str(uuid4()))
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    timestamp: Timestamp = field(default_factory=Timestamp.now)
    source: str = "unknown"
    version: str = "1.0.0"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "request_id": self.request_id,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.to_dict(),
            "source": self.source,
            "version": self.version,
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Safely get metadata value."""
        return self.metadata.get(key, default)

    def set_metadata(self, key: str, value: Any) -> None:
        """Set metadata value."""
        self.metadata[key] = value


# ============================================================================
# 4. ErrorResponse DATA MODEL
# ============================================================================

@dataclass
class ErrorResponse:
    """
    Structure for error responses with detailed error information.

    Attributes:
        status: Response status (should be ERROR or related)
        error_code: Error code/identifier (e.g., 'INVALID_INPUT', 'SERVER_ERROR')
        message: Human-readable error message
        details: Optional detailed error information
        context: Optional RequestContext for tracing
        trace_id: Optional trace ID for debugging
        timestamp: Response creation timestamp
    """
    status: ResponseStatus = ResponseStatus.ERROR
    error_code: str = "UNKNOWN_ERROR"
    message: str = "An error occurred"
    details: Optional[Dict[str, Any]] = None
    context: Optional[RequestContext] = None
    trace_id: Optional[str] = None
    timestamp: Timestamp = field(default_factory=Timestamp.now)

    def __post_init__(self):
        """Validate response structure."""
        if not isinstance(self.status, ResponseStatus):
            self.status = ResponseStatus.ERROR
        if self.details is None:
            self.details = {}
        if self.trace_id is None:
            self.trace_id = str(uuid4())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "status": self.status.value,
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
            "request_id": self.context.request_id if self.context else None,
            "trace_id": self.trace_id,
            "timestamp": self.timestamp.iso_format()
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def add_detail(self, key: str, value: Any) -> None:
        """Add a detail to the error details."""
        if self.details is None:
            self.details = {}
        self.details[key] = value


# ============================================================================
# 5. SuccessResponse DATA MODEL
# ============================================================================

@dataclass
class SuccessResponse:
    """
    Structure for successful responses with results.

    Attributes:
        status: Response status (SUCCESS or PARTIAL)
        data: The response data/results
        context: Optional RequestContext for tracing
        metadata: Optional response metadata
        timestamp: Response creation timestamp
    """
    status: ResponseStatus = ResponseStatus.SUCCESS
    data: Any = None
    context: Optional[RequestContext] = None
    metadata: Optional[Dict[str, Any]] = None
    timestamp: Timestamp = field(default_factory=Timestamp.now)

    def __post_init__(self):
        """Validate response structure."""
        if not isinstance(self.status, ResponseStatus):
            self.status = ResponseStatus.SUCCESS
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "status": self.status.value,
            "data": self.data,
            "request_id": self.context.request_id if self.context else None,
            "metadata": self.metadata,
            "timestamp": self.timestamp.iso_format()
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def set_data(self, data: Any) -> None:
        """Set response data."""
        self.data = data

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to response."""
        if self.metadata is None:
            self.metadata = {}
        self.metadata[key] = value


# ============================================================================
# 6. PagedResponse DATA MODEL (GENERIC)
# ============================================================================

@dataclass
class PagedResponse(Generic[T]):
    """
    Wrapper for paginated results with pagination metadata.

    Generic class that wraps any result type T with pagination information.

    Attributes:
        items: List of items for this page
        total_count: Total number of items across all pages
        page: Current page number (0-indexed)
        page_size: Number of items per page
        total_pages: Total number of pages
        has_next: Whether there's a next page
        has_previous: Whether there's a previous page
        status: Response status
        timestamp: Response creation timestamp
    """
    items: List[T] = field(default_factory=list)
    total_count: int = 0
    page: int = 0
    page_size: int = 10
    total_pages: int = 1
    has_next: bool = False
    has_previous: bool = False
    status: ResponseStatus = ResponseStatus.SUCCESS
    timestamp: Timestamp = field(default_factory=Timestamp.now)

    def __post_init__(self):
        """Calculate pagination values."""
        if self.page_size > 0:
            self.total_pages = (self.total_count + self.page_size - 1) // self.page_size
        self.has_next = self.page < (self.total_pages - 1)
        self.has_previous = self.page > 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "items": self.items,
            "pagination": {
                "page": self.page,
                "page_size": self.page_size,
                "total_count": self.total_count,
                "total_pages": self.total_pages,
                "has_next": self.has_next,
                "has_previous": self.has_previous
            },
            "status": self.status.value,
            "timestamp": self.timestamp.iso_format()
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def get_next_page_params(self) -> Optional[Dict[str, int]]:
        """Get parameters for fetching next page."""
        if self.has_next:
            return {"page": self.page + 1, "page_size": self.page_size}
        return None

    def get_previous_page_params(self) -> Optional[Dict[str, int]]:
        """Get parameters for fetching previous page."""
        if self.has_previous:
            return {"page": self.page - 1, "page_size": self.page_size}
        return None


# ============================================================================
# 7. BatchOperation DATA MODEL
# ============================================================================

@dataclass
class BatchOperation:
    """
    Structure for batch operation requests and status tracking.

    Attributes:
        batch_id: Unique identifier for the batch operation
        operation_type: Type of operation (e.g., 'analyze', 'scan', 'process')
        items: List of items to process in the batch
        status: Current batch status
        total_items: Total number of items
        processed_items: Number of processed items
        failed_items: Number of failed items
        context: Optional RequestContext
        metadata: Additional metadata
        created_at: Batch creation timestamp
        started_at: Batch start timestamp
        completed_at: Batch completion timestamp
    """
    batch_id: str = field(default_factory=lambda: str(uuid4()))
    operation_type: str = ""
    items: List[Any] = field(default_factory=list)
    status: ResponseStatus = ResponseStatus.PENDING
    total_items: int = 0
    processed_items: int = 0
    failed_items: int = 0
    context: Optional[RequestContext] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Timestamp = field(default_factory=Timestamp.now)
    started_at: Optional[Timestamp] = None
    completed_at: Optional[Timestamp] = None

    def __post_init__(self):
        """Initialize batch operation."""
        self.total_items = len(self.items)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "batch_id": self.batch_id,
            "operation_type": self.operation_type,
            "status": self.status.value,
            "progress": {
                "total": self.total_items,
                "processed": self.processed_items,
                "failed": self.failed_items,
                "percentage": self._get_progress_percentage()
            },
            "request_id": self.context.request_id if self.context else None,
            "timestamps": {
                "created": self.created_at.iso_format(),
                "started": self.started_at.iso_format() if self.started_at else None,
                "completed": self.completed_at.iso_format() if self.completed_at else None
            },
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def start(self) -> None:
        """Mark batch operation as started."""
        self.status = ResponseStatus.PENDING
        self.started_at = Timestamp.now()

    def complete(self) -> None:
        """Mark batch operation as completed."""
        self.completed_at = Timestamp.now()
        if self.failed_items == 0:
            self.status = ResponseStatus.SUCCESS
        elif self.processed_items > 0:
            self.status = ResponseStatus.PARTIAL
        else:
            self.status = ResponseStatus.ERROR

    def update_progress(self, processed: int, failed: int = 0) -> None:
        """Update batch progress."""
        self.processed_items = processed
        self.failed_items = failed

    def _get_progress_percentage(self) -> float:
        """Calculate progress percentage."""
        if self.total_items == 0:
            return 0.0
        return round((self.processed_items / self.total_items) * 100, 2)

    def get_progress_percentage(self) -> float:
        """Get progress percentage."""
        return self._get_progress_percentage()


# ============================================================================
# VALIDATION AND TESTING
# ============================================================================

def run_validation_tests():
    """
    Run validation tests for all common models.
    """
    print("=" * 70)
    print("Common Models - Validation Tests")
    print("=" * 70)
    print()

    # Test 1: Timestamp
    print("[TEST 1] Timestamp Model...")
    try:
        ts = Timestamp.now()
        assert ts.value is not None
        assert ts.iso_format() is not None
        assert ts.timestamp_seconds() > 0
        assert ts.to_dict() is not None
        print("  ✓ Timestamp creation successful")
        print(f"  ✓ ISO format: {ts.iso_format()}")
        print()
    except Exception as e:
        print(f"  ✗ Timestamp test failed: {str(e)}")
        print()

    # Test 2: RequestContext
    print("[TEST 2] RequestContext Model...")
    try:
        ctx = RequestContext(user_id="user123", source="api")
        assert ctx.request_id is not None
        assert ctx.user_id == "user123"
        assert ctx.source == "api"
        ctx.set_metadata("key", "value")
        assert ctx.get_metadata("key") == "value"
        assert ctx.to_json() is not None
        print("  ✓ RequestContext creation successful")
        print(f"  ✓ Request ID: {ctx.request_id}")
        print("  ✓ Metadata operations working")
        print()
    except Exception as e:
        print(f"  ✗ RequestContext test failed: {str(e)}")
        print()

    # Test 3: ResponseStatus
    print("[TEST 3] ResponseStatus Enum...")
    try:
        assert ResponseStatus.is_success(ResponseStatus.SUCCESS)
        assert ResponseStatus.is_success(ResponseStatus.PARTIAL)
        assert ResponseStatus.is_error(ResponseStatus.ERROR)
        assert ResponseStatus.is_error(ResponseStatus.TIMEOUT)
        print("  ✓ ResponseStatus.SUCCESS available")
        print("  ✓ ResponseStatus.ERROR available")
        print("  ✓ Status validation methods working")
        print()
    except Exception as e:
        print(f"  ✗ ResponseStatus test failed: {str(e)}")
        print()

    # Test 4: ErrorResponse
    print("[TEST 4] ErrorResponse Model...")
    try:
        ctx = RequestContext(user_id="user123")
        err = ErrorResponse(
            error_code="INVALID_INPUT",
            message="Input validation failed",
            context=ctx
        )
        assert err.status == ResponseStatus.ERROR
        assert err.error_code == "INVALID_INPUT"
        err.add_detail("field", "email")
        assert err.details is not None
        assert err.to_json() is not None
        print("  ✓ ErrorResponse creation successful")
        print(f"  ✓ Error code: {err.error_code}")
        print("  ✓ Detail management working")
        print()
    except Exception as e:
        print(f"  ✗ ErrorResponse test failed: {str(e)}")
        print()

    # Test 5: SuccessResponse
    print("[TEST 5] SuccessResponse Model...")
    try:
        ctx = RequestContext(user_id="user123")
        success = SuccessResponse(data={"result": "success"}, context=ctx)
        assert success.status == ResponseStatus.SUCCESS
        assert success.data is not None
        success.add_metadata("count", 1)
        assert success.metadata is not None
        assert success.to_json() is not None
        print("  ✓ SuccessResponse creation successful")
        print(f"  ✓ Data: {success.data}")
        print("  ✓ Metadata management working")
        print()
    except Exception as e:
        print(f"  ✗ SuccessResponse test failed: {str(e)}")
        print()

    # Test 6: PagedResponse
    print("[TEST 6] PagedResponse Model...")
    try:
        items = ["item1", "item2", "item3"]
        paged = PagedResponse(
            items=items,
            total_count=25,
            page=0,
            page_size=3
        )
        assert paged.total_pages == 9
        assert paged.has_next is True
        assert paged.has_previous is False
        next_params = paged.get_next_page_params()
        assert next_params is not None
        assert paged.to_json() is not None
        print("  ✓ PagedResponse creation successful")
        print(f"  ✓ Total pages: {paged.total_pages}")
        print(f"  ✓ Has next: {paged.has_next}")
        print("  ✓ Pagination calculation working")
        print()
    except Exception as e:
        print(f"  ✗ PagedResponse test failed: {str(e)}")
        print()

    # Test 7: BatchOperation
    print("[TEST 7] BatchOperation Model...")
    try:
        items = [{"id": 1}, {"id": 2}, {"id": 3}]
        batch = BatchOperation(
            operation_type="analyze",
            items=items,
            context=RequestContext(user_id="user123")
        )
        assert batch.batch_id is not None
        assert batch.total_items == 3
        assert batch.status == ResponseStatus.PENDING
        batch.start()
        batch.update_progress(2, 0)
        progress = batch.get_progress_percentage()
        assert progress > 0
        batch.complete()
        assert batch.completed_at is not None
        assert batch.to_json() is not None
        print("  ✓ BatchOperation creation successful")
        print(f"  ✓ Batch ID: {batch.batch_id}")
        print(f"  ✓ Progress: {progress}%")
        print("  ✓ Status transitions working")
        print()
    except Exception as e:
        print(f"  ✗ BatchOperation test failed: {str(e)}")
        print()

    # Summary
    print("=" * 70)
    print("✓ Common Models Validation Complete")
    print("=" * 70)
    print()
    print("Available Models:")
    print("  • ResponseStatus (Enum with 7 values)")
    print("  • Timestamp (Timezone-aware datetime wrapper)")
    print("  • RequestContext (Request metadata container)")
    print("  • ErrorResponse (Error details structure)")
    print("  • SuccessResponse (Success results structure)")
    print("  • PagedResponse (Generic pagination wrapper)")
    print("  • BatchOperation (Batch operation tracker)")


if __name__ == "__main__":
    run_validation_tests()