from __future__ import annotations

import time
from collections import defaultdict, deque


class _Pipeline:
    def __init__(self, redis: "AsyncFakeRedis"):
        self._redis = redis
        self._ops = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def delete(self, key: str):
        self._ops.append(("delete", (key,), {}))
        return self

    def sadd(self, key: str, *values: str):
        self._ops.append(("sadd", (key, *values), {}))
        return self

    def sismember(self, key: str, value: str):
        self._ops.append(("sismember", (key, value), {}))
        return self

    def incr(self, key: str):
        self._ops.append(("incr", (key,), {}))
        return self

    def expire(self, key: str, seconds: int):
        self._ops.append(("expire", (key, seconds), {}))
        return self

    def lpush(self, key: str, value: str):
        self._ops.append(("lpush", (key, value), {}))
        return self

    def ltrim(self, key: str, start: int, stop: int):
        self._ops.append(("ltrim", (key, start, stop), {}))
        return self

    async def execute(self):
        results = []
        for name, args, kwargs in self._ops:
            fn = getattr(self._redis, name)
            results.append(await fn(*args, **kwargs))
        self._ops.clear()
        return results


class AsyncFakeRedis:
    """
    Minimal async Redis fake covering the subset used by this repo's services/tests.
    Not a complete Redis implementation.
    """

    def __init__(self):
        self._kv = {}
        self._sets = defaultdict(set)
        self._lists = defaultdict(deque)
        self._expires_at = {}  # key -> epoch seconds

    def _is_expired(self, key: str) -> bool:
        exp = self._expires_at.get(key)
        return exp is not None and time.time() >= exp

    def _maybe_expire(self, key: str):
        if self._is_expired(key):
            self._kv.pop(key, None)
            self._sets.pop(key, None)
            self._lists.pop(key, None)
            self._expires_at.pop(key, None)

    async def close(self):
        return None

    async def ping(self):
        return True

    def pipeline(self, transaction: bool = True):  # noqa: ARG002
        return _Pipeline(self)

    async def get(self, key: str):
        self._maybe_expire(key)
        return self._kv.get(key)

    async def set(self, key: str, value: str, ex: int | None = None):
        self._kv[key] = value
        if ex is not None:
            self._expires_at[key] = time.time() + ex
        return True

    async def delete(self, key: str):
        existed = 0
        if key in self._kv:
            existed = 1
            del self._kv[key]
        if key in self._sets:
            existed = 1
            del self._sets[key]
        if key in self._lists:
            existed = 1
            del self._lists[key]
        self._expires_at.pop(key, None)
        return existed

    async def incr(self, key: str):
        self._maybe_expire(key)
        val = int(self._kv.get(key) or 0) + 1
        self._kv[key] = str(val)
        return val

    async def expire(self, key: str, seconds: int):
        self._expires_at[key] = time.time() + seconds
        return True

    async def ttl(self, key: str):
        if key not in self._expires_at:
            return -1
        return max(0, int(self._expires_at[key] - time.time()))

    async def sadd(self, key: str, *values: str):
        self._sets[key].update(values)
        return len(values)

    async def sismember(self, key: str, value: str):
        return value in self._sets.get(key, set())

    async def lpush(self, key: str, value: str):
        self._lists[key].appendleft(value)
        return len(self._lists[key])

    async def ltrim(self, key: str, start: int, stop: int):
        items = list(self._lists[key])
        self._lists[key] = deque(items[start : stop + 1])
        return True

    async def lrange(self, key: str, start: int, stop: int):
        items = list(self._lists[key])
        if stop < 0:
            stop = len(items) + stop
        return items[start : stop + 1]

    async def llen(self, key: str):
        return len(self._lists[key])


