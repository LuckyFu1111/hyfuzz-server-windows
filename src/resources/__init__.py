"""Resource management utilities."""

from .rate_limiter import RateLimiter
from .quota_manager import QuotaManager
from .resource_allocator import ResourceAllocator

__all__ = ["RateLimiter", "QuotaManager", "ResourceAllocator"]


if __name__ == "__main__":
    limiter = RateLimiter(limit=2, interval=1)
    print(limiter.allow())
    print(limiter.allow())
    print(limiter.allow())
