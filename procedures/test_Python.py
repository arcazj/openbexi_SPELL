# @procedure test_Python
# @description Python runtime validation across 39 language and standard-library topics
# @language-profile python-stdlib/3.13
"""Validate Python language and standard-library capabilities in the isolated executor."""

from __future__ import annotations

import abc
import argparse
import ast
import asyncio
import base64
import bisect
import bz2
import cmath
import configparser
import contextvars
import csv
import ctypes
import dis
import gc
import gzip
import hashlib
import heapq
import hmac
import importlib
import importlib.util
import inspect
import io
import ipaddress
import itertools
import json
import logging
import lzma
import math
import mmap
import multiprocessing
import operator
import os
import pickle
import platform
import queue
import random
import re
import secrets
import shlex
import shutil
import signal
import socket
import sqlite3
import ssl
import statistics
import struct
import subprocess
import sys
import tarfile
import textwrap
import threading
import time
import traceback
import tracemalloc
import uuid
import warnings
import weakref
import zipfile
from array import array
from collections import ChainMap, Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, localcontext
from enum import Enum
from fractions import Fraction
from functools import lru_cache, reduce, wraps
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType, SimpleNamespace
from typing import Any, Callable, Iterator, Optional, TypeVar
from urllib.parse import parse_qs, urlencode, urlparse


T = TypeVar("T")
SCOPE_COUNTER = 0
CHECK_COUNTER = 0
SKIP_COUNTER = 0


def check(label: str, actual: Any, expected: Any) -> None:
    """Show an example and verify it, even when Python runs with -O."""
    global CHECK_COUNTER
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")
    CHECK_COUNTER += 1
    print(f"  {label}: {actual!r}")


def check_true(label: str, condition: Any) -> None:
    """Verify an invariant without requiring an environment-specific exact value."""
    check(label, bool(condition), True)


def skip(label: str, reason: str) -> None:
    """Report an unavailable optional/platform capability without failing the suite."""
    global SKIP_COUNTER
    SKIP_COUNTER += 1
    print(f"  {label}: SKIPPED ({reason})")


def _multiprocessing_square(value: int, connection: Any) -> None:
    """Top-level worker so the multiprocessing spawn start method can pickle it."""
    try:
        connection.send(("ok", value * value))
    except BaseException as error:  # pragma: no cover - child process diagnostics
        connection.send(("error", repr(error)))
    finally:
        connection.close()


def demo_types() -> None:
    """Assignment, numeric types, None, conversions, and operators."""
    integer, floating, boolean, nothing = 7, 2.5, True, None
    check("int, float, bool, None", (integer, floating, boolean, nothing),
          (7, 2.5, True, None))
    check("complex numbers", (2 + 3j) + (1 - 1j), 3 + 2j)
    check("arbitrary precision integers", 2**100 > 2**64, True)
    check("arithmetic + - * / // % **",
          (7 + 2, 7 - 2, 7 * 2, 7 / 2, 7 // 2, 7 % 2, 7**2),
          (9, 5, 14, 3.5, 3, 1, 49))
    check("bitwise & | ^ << >> ~",
          (6 & 3, 6 | 3, 6 ^ 3, 3 << 1, 6 >> 1, ~0),
          (2, 7, 5, 6, 3, -1))
    check("comparison and boolean operators", 1 < integer <= 10 and not False, True)
    check("short circuit fallback", "" or "default", "default")
    check("truthiness", (bool([]), bool([0]), bool(0)), (False, True, False))
    check("type conversion", (int("42"), float("2.5"), str(7)), (42, 2.5, "7"))
    check("isinstance", isinstance(integer, int), True)
    check("None identity", nothing is None, True)
    integer += 3
    check("augmented assignment", integer, 10)


def demo_strings() -> None:
    """Unicode strings, indexing, slicing, formatting, and bytes."""
    text = "Python"
    check("indexing and negative indexing", (text[0], text[-1]), ("P", "n"))
    check("slicing and stride", (text[1:4], text[::-1], text[::2]),
          ("yth", "nohtyP", "Pto"))
    check("string methods", "  hello world  ".strip().title(), "Hello World")
    check("split and join", "-".join("red green blue".split()), "red-green-blue")
    check("replacement and membership", (text.replace("Py", "Jy"), "tho" in text),
          ("Jython", True))
    check("f-string formatting", f"{text}: {3.14159:.2f}", "Python: 3.14")
    check("raw string", r"a\nb", "a\\nb")
    check("multiline string", """first
second""".splitlines(), ["first", "second"])
    encoded = "caf\u00e9".encode("utf-8")
    check("Unicode and bytes round trip", encoded.decode("utf-8"), "caf\u00e9")
    check("bytes index is an integer", b"ABC"[0], 65)
    buffer = bytearray(b"cat")
    buffer[0] = ord("b")
    check("mutable bytearray", bytes(buffer), b"bat")


def demo_collections() -> None:
    """Lists, tuples, dictionaries, sets, mutation, identity, and unpacking."""
    numbers = [1, 2, 3]
    alias = numbers
    copied = numbers.copy()
    alias.append(4)
    check("shared mutable reference", alias is numbers, True)
    check("copy has independent outer list", copied, [1, 2, 3])
    check("list equality versus identity", (copied == [1, 2, 3], copied is numbers),
          (True, False))
    numbers[1:3] = [20, 30]
    check("slice assignment", numbers, [1, 20, 30, 4])
    del numbers[1]
    check("delete and pop", (numbers.pop(), numbers), (4, [1, 30]))
    first, *middle, last = (10, 20, 30, 40)
    check("tuple and starred unpacking", (first, middle, last), (10, [20, 30], 40))
    first, last = last, first
    check("parallel assignment swap", (first, last), (40, 10))
    person = {"name": "Ada", "age": 36}
    person["language"] = "Python"
    check("dict get with default", person.get("missing", "unknown"), "unknown")
    check("dict merge and unpacking", {**person, "age": 37}["age"], 37)
    check("dict union (Python 3.9+)", {"a": 1} | {"b": 2}, {"a": 1, "b": 2})
    check("dictionary iteration preserves insertion order", list(person),
          ["name", "age", "language"])
    left, right = {1, 2, 3}, {3, 4}
    check("set union, intersection, difference, symmetric difference",
          (left | right, left & right, left - right, left ^ right),
          ({1, 2, 3, 4}, {3}, {1, 2}, {1, 2, 4}))
    check("immutable frozenset as a dict key", {frozenset({1, 2}): "pair"}[frozenset({2, 1})],
          "pair")


def demo_control_flow() -> None:
    """if/elif/else, conditional expressions, loops, break, and continue."""
    score = 85
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    else:
        grade = "C"
    check("if / elif / else", grade, "B")
    check("conditional expression", "even" if score % 2 == 0 else "odd", "odd")
    selected = []
    for number in range(6):
        if number == 2:
            continue
        if number == 5:
            break
        selected.append(number)
    check("for, range, continue, break", selected, [0, 1, 3, 4])
    countdown = 3
    while countdown:
        countdown -= 1
    else:
        check("while / else on normal completion", countdown, 0)
    for number in [1, 3, 5]:
        if number % 2 == 0:
            break
    else:
        check("for / else when no break occurs", "no even number", "no even number")
    check("enumerate", list(enumerate(["a", "b"], start=1)), [(1, "a"), (2, "b")])
    check("zip", list(zip(["a", "b"], [1, 2])), [("a", 1), ("b", 2)])
    if (length := len(selected)) > 2:
        check("assignment expression :=", length, 4)
    if False:
        pass  # A placeholder statement; no operation.


def demo_comprehensions() -> None:
    """List, set, dict, nested comprehensions, and generator expressions."""
    check("filtered list comprehension", [n * n for n in range(6) if n % 2 == 0],
          [0, 4, 16])
    check("set comprehension", {n % 3 for n in range(8)}, {0, 1, 2})
    check("dict comprehension", {n: n * n for n in range(3)}, {0: 0, 1: 1, 2: 4})
    check("nested comprehension", [(x, y) for x in range(2) for y in range(2)],
          [(0, 0), (0, 1), (1, 0), (1, 1)])
    check("lazy generator expression", sum(n * n for n in range(4)), 14)
    check("any and all", (any(n > 2 for n in range(4)), all(n < 4 for n in range(4))),
          (True, True))


def demo_functions() -> None:
    """Parameters, defaults, annotations, first-class functions, and recursion."""
    def greet(name: str, /, greeting: str = "Hello", *, punctuation: str = "!") -> str:
        # '/' makes name positional-only; '*' makes punctuation keyword-only.
        return f"{greeting}, {name}{punctuation}"

    def collect(*args: int, **kwargs: str) -> tuple[tuple[int, ...], dict[str, str]]:
        return args, kwargs

    def append_item(item: int, items: Optional[list[int]] = None) -> list[int]:
        # None avoids accidentally sharing a mutable default between calls.
        if items is None:
            items = []
        items.append(item)
        return items

    def factorial(number: int) -> int:
        if number < 0:
            raise ValueError("factorial requires a nonnegative integer")
        return 1 if number < 2 else number * factorial(number - 1)

    def apply(function: Callable[[T], T], value: T) -> T:
        return function(value)

    check("positional-only, default, keyword-only", greet("Ada", punctuation="."),
          "Hello, Ada.")
    check("*args, **kwargs, call unpacking", collect(*[1, 2], **{"name": "Ada"}),
          ((1, 2), {"name": "Ada"}))
    check("fresh mutable defaults", (append_item(1), append_item(2)), ([1], [2]))
    check("recursive function", factorial(5), 120)
    check("lambda and first-class function", apply(lambda number: number * 2, 6), 12)
    check("sorted with key function", sorted(["pear", "fig", "apple"], key=len),
          ["fig", "pear", "apple"])
    check("map and filter", list(map(lambda n: n * 2, filter(lambda n: n > 1, [1, 2, 3]))),
          [4, 6])


def demo_scope_and_decorators() -> None:
    """Local, enclosing, and global scope; closures; function decorators."""
    global SCOPE_COUNTER
    previous = SCOPE_COUNTER
    SCOPE_COUNTER += 1
    check("global rebinding", SCOPE_COUNTER, previous + 1)

    def make_counter() -> Callable[[], int]:
        count = 0

        def increment() -> int:
            nonlocal count
            count += 1
            return count

        return increment

    counter = make_counter()
    check("closure and nonlocal", (counter(), counter()), (1, 2))

    def double_result(function: Callable[..., int]) -> Callable[..., int]:
        @wraps(function)  # Preserve the wrapped function's name and docstring.
        def wrapper(*args: Any, **kwargs: Any) -> int:
            return 2 * function(*args, **kwargs)

        return wrapper

    @double_result
    def add(left: int, right: int) -> int:
        """Add two numbers before the decorator doubles the result."""
        return left + right

    check("custom decorator", add(2, 3), 10)
    check("decorator preserves metadata", add.__name__, "add")

    @lru_cache(maxsize=None)
    def fibonacci(number: int) -> int:
        return number if number < 2 else fibonacci(number - 1) + fibonacci(number - 2)

    check("memoization decorator", fibonacci(10), 55)
    check("memoization reuses results", fibonacci.cache_info().hits > 0, True)


def demo_iterators() -> None:
    """Iteration protocol, next, generator functions, and yield from."""
    iterator = iter([10, 20])
    check("iter and next", (next(iterator), next(iterator), next(iterator, "done")),
          (10, 20, "done"))

    class Countdown:
        def __init__(self, start: int) -> None:
            self.current = start

        def __iter__(self) -> Countdown:
            return self

        def __next__(self) -> int:
            if self.current <= 0:
                raise StopIteration
            value = self.current
            self.current -= 1
            return value

    def squares(limit: int) -> Iterator[int]:
        for number in range(limit):
            yield number * number

    def combined() -> Iterator[int]:
        yield from squares(3)
        yield from [9, 16]

    check("custom iterator protocol", list(Countdown(3)), [3, 2, 1])
    generated = squares(3)
    check("generator resumes after yield", (next(generated), list(generated)), (0, [1, 4]))
    check("exhausted generator", list(generated), [])
    check("yield from delegation", list(combined()), [0, 1, 4, 9, 16])


def demo_exceptions() -> None:
    """raise, custom exceptions, chaining, try/except/else/finally, and assert."""
    class InvalidAgeError(ValueError):
        pass

    def parse_age(text: str) -> int:
        try:
            age = int(text)
        except ValueError as error:
            raise InvalidAgeError("age must be an integer") from error
        if age < 0:
            raise InvalidAgeError("age cannot be negative")
        return age

    events = []
    try:
        parse_age("unknown")
    except InvalidAgeError as error:
        events.append("except")
        check("exception chaining", isinstance(error.__cause__, ValueError), True)
    else:
        events.append("else")
    finally:
        events.append("finally")
    check("except and finally", events, ["except", "finally"])
    try:
        age = parse_age("36")
    except InvalidAgeError:
        raise AssertionError("valid age unexpectedly failed")
    else:
        check("else runs after successful try", age, 36)
    try:
        parse_age("-1")
    except InvalidAgeError as error:
        check("explicit raise", str(error), "age cannot be negative")
    else:
        raise AssertionError("negative age should raise InvalidAgeError")
    assert age >= 0, "Assertions express developer assumptions; -O disables them."
    check("assert statement example", age >= 0, True)


def demo_classes() -> None:
    """Classes, inheritance, super, properties, methods, and duck typing."""
    class Animal:
        kingdom = "animal"  # Shared class attribute.

        def __init__(self, name: str) -> None:
            self.name = name  # Per-instance attribute.

        def speak(self) -> str:
            return "a sound"

        @property
        def name(self) -> str:
            return self._name

        @name.setter
        def name(self, value: str) -> None:
            if not value.strip():
                raise ValueError("name cannot be blank")
            self._name = value.strip()

        @classmethod
        def from_text(cls, text: str) -> Animal:
            return cls(text)

        @staticmethod
        def is_valid_name(name: str) -> bool:
            return bool(name.strip())

    class Dog(Animal):
        def __init__(self, name: str, breed: str = "mixed") -> None:
            super().__init__(name)
            self.breed = breed

        def speak(self) -> str:
            return f"{self.name} says woof"

    class Robot:
        def speak(self) -> str:
            return "beep"

    def announce(speaker: Any) -> str:
        return speaker.speak()  # Any object with speak() can participate.

    dog = Dog.from_text("  Fido  ")
    check("inheritance and classmethod", (isinstance(dog, Animal), dog.breed), (True, "mixed"))
    check("property setter", dog.name, "Fido")
    dog.name = "Rex"
    check("overridden method", dog.speak(), "Rex says woof")
    check("class attribute and staticmethod", (Dog.kingdom, Animal.is_valid_name(" ")),
          ("animal", False))
    check("polymorphism and duck typing", [announce(dog), announce(Robot())],
          ["Rex says woof", "beep"])
    try:
        dog.name = " "
    except ValueError as error:
        check("property validation", str(error), "name cannot be blank")
    else:
        raise AssertionError("blank name should raise ValueError")


def demo_dataclasses() -> None:
    """Dataclasses, enums, and special methods for Python's object protocols."""
    @dataclass(frozen=True)
    class Vector:
        x: int
        y: int

        def __add__(self, other: Any) -> Any:
            if not isinstance(other, Vector):
                return NotImplemented
            return Vector(self.x + other.x, self.y + other.y)

        def __iter__(self) -> Iterator[int]:
            yield self.x
            yield self.y

        def __len__(self) -> int:
            return 2

        def __getitem__(self, index: int) -> int:
            return (self.x, self.y)[index]

        def __call__(self, scale: int) -> Vector:
            return Vector(self.x * scale, self.y * scale)

        def __str__(self) -> str:
            return f"({self.x}, {self.y})"

    @dataclass
    class Team:
        members: list[str] = field(default_factory=list)

    class Status(Enum):
        READY = "ready"
        DONE = "done"

    vector = Vector(2, 3)
    check("dataclass generated equality", vector == Vector(2, 3), True)
    check("dataclass serialization", asdict(vector), {"x": 2, "y": 3})
    check("operator overloading __add__", vector + Vector(1, 4), Vector(3, 7))
    check("__iter__, __len__, __getitem__", (tuple(vector), len(vector), vector[0]),
          ((2, 3), 2, 2))
    check("callable object __call__", vector(2), Vector(4, 6))
    check("__str__ and generated __repr__", (str(vector), repr(vector)),
          ("(2, 3)", f"{Vector.__qualname__}(x=2, y=3)"))
    check("frozen dataclass is hashable", {vector: "point"}[Vector(2, 3)], "point")
    first, second = Team(), Team()
    first.members.append("Ada")
    check("default_factory avoids shared lists", second.members, [])
    check("enum name and value", (Status.READY.name, Status.READY.value), ("READY", "ready"))


def demo_context_managers() -> None:
    """with, file I/O, pathlib, and both forms of custom context manager."""
    with TemporaryDirectory(prefix="python-features-") as directory:
        path = Path(directory) / "example.txt"
        with path.open("w", encoding="utf-8") as stream:
            stream.write("first line\nsecond line\n")
        check("with closes file", stream.closed, True)
        with path.open(encoding="utf-8") as stream:
            check("iterate text file", [line.rstrip("\n") for line in stream],
                  ["first line", "second line"])
        binary_path = path.with_suffix(".bin")
        binary_path.write_bytes(b"\x00\x01\x02")
        check("binary file I/O", binary_path.read_bytes(), b"\x00\x01\x02")
    check("temporary files cleaned up", path.exists(), False)

    events = []

    @contextmanager
    def managed_resource() -> Iterator[str]:
        events.append("acquire")
        try:
            yield "resource"
        finally:
            events.append("release")

    try:
        with managed_resource() as resource:
            check("contextmanager yields a resource", resource, "resource")
            raise ValueError("simulate failure")
    except ValueError:
        pass
    check("cleanup also runs after exceptions", events, ["acquire", "release"])

    class ManagedResource:
        def __enter__(self) -> str:
            events.append("enter")
            return "class resource"

        def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
            events.append("exit")
            return False  # Propagate exceptions instead of suppressing them.

    with ManagedResource() as resource:
        check("__enter__ and __exit__ protocol", resource, "class resource")
    check("class context manager lifecycle", events[-2:], ["enter", "exit"])


def demo_standard_library() -> None:
    """Module imports and useful standard-library facilities."""
    check("imported math module", math.isclose(math.sqrt(81), 9), True)
    payload = {"name": "Ada", "skills": ["Python", "math"]}
    check("JSON serialization round trip", json.loads(json.dumps(payload)), payload)
    check("regular expressions", re.findall(r"\d+", "order 12 costs 34"), ["12", "34"])
    check("Counter", Counter("banana")["a"], 3)
    grouped: defaultdict[str, list[str]] = defaultdict(list)
    for word in ["apple", "ant", "boat"]:
        grouped[word[0]].append(word)
    check("defaultdict", dict(grouped), {"a": ["apple", "ant"], "b": ["boat"]})
    check("date arithmetic", (date(2024, 2, 28) + timedelta(days=1)).isoformat(), "2024-02-29")
    check("Decimal arithmetic", Decimal("0.1") + Decimal("0.2"), Decimal("0.3"))


def demo_async() -> None:
    """async def, await, concurrent tasks, async for, and async with."""
    async def square(number: int) -> int:
        await asyncio.sleep(0)  # Yield control without a real-time delay.
        return number * number

    async def numbers(limit: int):
        for number in range(limit):
            await asyncio.sleep(0)
            yield number

    class AsyncResource:
        async def __aenter__(self) -> str:
            await asyncio.sleep(0)
            return "async resource"

        async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
            return False

    async def run() -> None:
        tasks = [asyncio.create_task(square(number)) for number in range(4)]
        check("async tasks and gather", await asyncio.gather(*tasks), [0, 1, 4, 9])
        collected = [number async for number in numbers(3)]
        check("async generator and comprehension", collected, [0, 1, 2])
        async with AsyncResource() as resource:
            check("async context manager", resource, "async resource")

    asyncio.run(run())  # The synchronous CLI owns its event loop.


def demo_threads() -> None:
    """Standard-library thread pool, futures, and orderly executor shutdown."""
    def square(number: int) -> int:
        return number * number

    # Threads illustrate concurrency; CPU speedup depends on the Python runtime.
    with ThreadPoolExecutor(max_workers=2) as executor:
        check("thread pool map preserves input order", list(executor.map(square, range(4))),
              [0, 1, 4, 9])
        future = executor.submit(square, 5)
        check("future result", future.result(), 25)


def demo_pattern_matching() -> None:
    """Structural pattern matching, available starting with Python 3.10."""
    if sys.version_info < (3, 10):
        print("  SKIPPED: match / case requires Python 3.10+.")
        return

    # Compile this fixed, trusted example only on supported interpreters, keeping
    # the rest of this file runnable on Python 3.9. No user input is executed.
    source = '''def describe(value):
    match value:
        case {"name": str(name), "age": int(age)} if age >= 18:
            return f"adult: {name}"
        case [x, y]:
            return f"pair: {x}, {y}"
        case "yes" | "y":
            return "affirmative"
        case _:
            return "other"
'''
    namespace: dict[str, Any] = {}
    exec(compile(source, "<pattern-matching-example>", "exec"), namespace)
    describe = namespace["describe"]
    check("mapping and class patterns with guard", describe({"name": "Ada", "age": 36}),
          "adult: Ada")
    check("failed guard falls through", describe({"name": "Ada", "age": 12}), "other")
    check("sequence pattern and captures", describe([2, 3]), "pair: 2, 3")
    check("OR pattern", describe("y"), "affirmative")
    check("wildcard pattern", describe(None), "other")



def demo_runtime() -> None:
    """Interpreter metadata, encodings, limits, recursion, frames, and runtime knobs."""
    check("Python major version", sys.version_info.major, 3)
    check_true("implementation name exists", bool(sys.implementation.name))
    check_true("platform implementation exists", bool(platform.python_implementation()))
    check_true("sys.executable is configured", bool(sys.executable))
    check_true("filesystem encoding exists", bool(sys.getfilesystemencoding()))
    check("default text encoding", sys.getdefaultencoding().lower(), "utf-8")
    check_true("native word-size integer limit", sys.maxsize >= 2**31 - 1)
    check_true("float runtime metadata", sys.float_info.max > 1.0)
    check_true("integer runtime metadata", sys.int_info.bits_per_digit > 0)
    check_true("object size is measurable", sys.getsizeof(object()) > 0)
    check("byte order is valid", sys.byteorder in {"little", "big"}, True)
    check_true("prefix is configured", bool(sys.prefix))
    check_true("base prefix is configured", bool(getattr(sys, "base_prefix", sys.prefix)))

    original_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(original_limit + 1)
    check("recursion limit can be changed", sys.getrecursionlimit(), original_limit + 1)
    sys.setrecursionlimit(original_limit)

    original_interval = sys.getswitchinterval()
    sys.setswitchinterval(max(original_interval / 2.0, 1e-6))
    check_true("thread switch interval is positive", sys.getswitchinterval() > 0)
    sys.setswitchinterval(original_interval)

    frame_getter = getattr(sys, "_getframe", None)
    if frame_getter is None:
        skip("frame introspection", "sys._getframe is implementation-specific")
    else:
        check("frame function name", frame_getter().f_code.co_name, "demo_runtime")

    gil_query = getattr(sys, "_is_gil_enabled", None)
    if callable(gil_query):
        check("GIL runtime state is boolean", isinstance(gil_query(), bool), True)
    else:
        skip("GIL runtime state", "sys._is_gil_enabled is not available on this interpreter")


def demo_builtin_protocols() -> None:
    """Built-ins, memory views, callable iterators, slices, formatting, and protocols."""
    check("divmod", divmod(17, 5), (3, 2))
    check("three-argument pow", pow(7, 4, 5), 1)
    check("round", round(3.14159, 3), 3.142)
    check("min/max/sum", (min(3, 1, 2), max(3, 1, 2), sum([1, 2, 3])), (1, 3, 6))
    check("reversed", list(reversed([1, 2, 3])), [3, 2, 1])
    check("slice.indices", slice(None, None, -1).indices(5), (4, -1, -1))
    check("format protocol", format(255, "#06x"), "0x00ff")
    check("ascii escaping", ascii("café"), "'caf\\xe9'")

    values = iter([1, 2, 3, 0, 9])
    check("iter(callable, sentinel)", list(iter(lambda: next(values), 0)), [1, 2, 3])

    data = bytearray(b"abc")
    view = memoryview(data)
    view[1] = ord("Z")
    check("memoryview zero-copy mutation", bytes(data), b"aZc")
    view.release()

    mapping = {"a": 1}
    keys = mapping.keys()
    mapping["b"] = 2
    check("dict views are dynamic", list(keys), ["a", "b"])

    if sys.version_info >= (3, 10):
        check("zip(strict=True)", list(zip([1, 2], ["a", "b"], strict=True)), [(1, "a"), (2, "b")])
        try:
            list(zip([1], [1, 2], strict=True))
        except ValueError:
            check("zip strict detects unequal lengths", True, True)
        else:
            raise AssertionError("zip(strict=True) should reject unequal lengths")
    else:
        skip("zip(strict=True)", "requires Python 3.10+")


def demo_code_execution() -> None:
    """compile, eval, exec, AST parsing, code objects, and dynamic namespaces."""
    expression = compile("(x + 2) * 3", "<runtime-expression>", "eval")
    check("compile + eval", eval(expression, {"x": 4}), 18)

    namespace: dict[str, Any] = {}
    statement = compile("answer = sum(i*i for i in range(4))", "<runtime-statement>", "exec")
    exec(statement, namespace)
    check("compile + exec", namespace["answer"], 14)
    check("code object filename", statement.co_filename, "<runtime-statement>")

    tree = ast.parse("value = 6 * 7")
    check("AST module", type(tree).__name__, "Module")
    assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
    check("AST traversal", len(assignments), 1)
    if hasattr(ast, "unparse"):
        check_true("AST unparse returns source", "value" in ast.unparse(tree))
    else:
        skip("AST unparse", "not available on this Python version")


def demo_object_model() -> None:
    """Descriptors, slots, ABCs, metaclasses, MRO, dynamic attributes, and proxy mappings."""
    class Positive:
        def __set_name__(self, owner: type[Any], name: str) -> None:
            self.storage_name = f"_{name}"

        def __get__(self, instance: Any, owner: type[Any]) -> Any:
            if instance is None:
                return self
            return getattr(instance, self.storage_name)

        def __set__(self, instance: Any, value: int) -> None:
            if value <= 0:
                raise ValueError("value must be positive")
            setattr(instance, self.storage_name, value)

    class Account:
        balance = Positive()
        __slots__ = ("_balance",)

        def __init__(self, balance: int) -> None:
            self.balance = balance

    account = Account(10)
    account.balance = 25
    check("data descriptor", account.balance, 25)
    check("__slots__ removes instance __dict__", hasattr(account, "__dict__"), False)
    try:
        account.balance = 0
    except ValueError as error:
        check("descriptor validation", str(error), "value must be positive")
    else:
        raise AssertionError("descriptor should reject non-positive values")

    class PluginMeta(type):
        names: list[str] = []

        def __new__(mcls, name: str, bases: tuple[type[Any], ...], attrs: dict[str, Any]):
            cls = super().__new__(mcls, name, bases, attrs)
            if name != "Plugin":
                mcls.names.append(name)
            return cls

    class Plugin(metaclass=PluginMeta):
        pass

    class ExamplePlugin(Plugin):
        pass

    check("metaclass class creation hook", "ExamplePlugin" in PluginMeta.names, True)

    class Shape(abc.ABC):
        @abc.abstractmethod
        def area(self) -> int:
            raise NotImplementedError

    class Square(Shape):
        def __init__(self, side: int) -> None:
            self.side = side

        def area(self) -> int:
            return self.side * self.side

    check("abstract base class", Square(4).area(), 16)

    class Left:
        label = "left"

    class Right:
        label = "right"

    class Child(Left, Right):
        pass

    check("method resolution order", Child.label, "left")
    check("MRO includes both bases", [base.__name__ for base in Child.__mro__[:3]], ["Child", "Left", "Right"])

    class Fallback:
        def __getattr__(self, name: str) -> str:
            return f"computed:{name}"

    check("__getattr__ fallback", Fallback().missing, "computed:missing")
    check("SimpleNamespace", vars(SimpleNamespace(a=1, b=2)), {"a": 1, "b": 2})

    source = {"answer": 42}
    proxy = MappingProxyType(source)
    source["extra"] = 1
    check("mapping proxy reflects source", dict(proxy), {"answer": 42, "extra": 1})
    try:
        proxy["answer"] = 0  # type: ignore[index]
    except TypeError:
        check("mapping proxy is read-only", True, True)
    else:
        raise AssertionError("MappingProxyType should be read-only")


def demo_import_system() -> None:
    """Module discovery, packages, dynamic imports, module specs, and cleanup."""
    check("dynamic standard-library import", importlib.import_module("math").sqrt(49), 7.0)
    check_true("find_spec finds json", importlib.util.find_spec("json") is not None)

    package_name = f"runtime_pkg_{uuid.uuid4().hex}"
    with TemporaryDirectory(prefix="python-import-") as directory:
        root = Path(directory)
        package = root / package_name
        package.mkdir()
        (package / "__init__.py").write_text("from .worker import answer\n", encoding="utf-8")
        (package / "worker.py").write_text("def answer():\n    return 6 * 7\n", encoding="utf-8")
        sys.path.insert(0, str(root))
        importlib.invalidate_caches()
        try:
            module = importlib.import_module(package_name)
            check("temporary package import", module.answer(), 42)
            check("package metadata", module.__package__, package_name)
            check_true("module spec exists", module.__spec__ is not None)
        finally:
            sys.path.remove(str(root))
            for key in list(sys.modules):
                if key == package_name or key.startswith(package_name + "."):
                    del sys.modules[key]
            importlib.invalidate_caches()


def demo_filesystem() -> None:
    """os/pathlib filesystem APIs, descriptors, metadata, traversal, globbing, and shutil."""
    env_name = f"PY_RUNTIME_TEST_{os.getpid()}"
    previous = os.environ.get(env_name)
    os.environ[env_name] = "active"
    check("environment variable round trip", os.getenv(env_name), "active")
    if previous is None:
        del os.environ[env_name]
    else:
        os.environ[env_name] = previous

    with TemporaryDirectory(prefix="python-fs-") as directory:
        root = Path(directory)
        nested = root / "a" / "b"
        nested.mkdir(parents=True)
        first = nested / "one.txt"
        first.write_text("alpha\nbeta\n", encoding="utf-8")
        check("pathlib text I/O", first.read_text(encoding="utf-8"), "alpha\nbeta\n")
        check_true("stat reports size", first.stat().st_size > 0)
        check("path properties", (first.name, first.suffix, first.stem), ("one.txt", ".txt", "one"))

        fd_path = root / "fd.bin"
        descriptor = os.open(fd_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, b"abc")
        finally:
            os.close(descriptor)
        check("low-level file descriptor I/O", fd_path.read_bytes(), b"abc")

        copied = root / "copy.txt"
        shutil.copy2(first, copied)
        check("shutil.copy2", copied.read_text(encoding="utf-8"), "alpha\nbeta\n")
        moved = root / "moved.txt"
        shutil.move(str(copied), str(moved))
        check("shutil.move", (copied.exists(), moved.exists()), (False, True))

        found = sorted(path.name for path in root.rglob("*.txt"))
        check("recursive glob", found, ["moved.txt", "one.txt"])
        walked = sorted(Path(base).name for base, _, _ in os.walk(root))
        check_true("os.walk traverses nested directories", {"python-fs-", "a", "b"}.issubset({name if name != root.name else "python-fs-" for name in walked}))
        entries = {entry.name for entry in os.scandir(root)}
        check_true("os.scandir lists entries", {"a", "fd.bin", "moved.txt"}.issubset(entries))

        symlink = root / "link-to-one"
        try:
            symlink.symlink_to(first)
            check("symbolic link", symlink.read_text(encoding="utf-8"), "alpha\nbeta\n")
        except (OSError, NotImplementedError) as error:
            skip("symbolic link", f"not permitted/supported: {error}")


def demo_text_and_io() -> None:
    """In-memory streams, CSV, INI parsing, text wrapping, shell lexing, and redirects."""
    stream = io.StringIO()
    stream.write("hello")
    stream.seek(0)
    check("StringIO", stream.read(), "hello")

    binary = io.BytesIO()
    binary.write(b"\x00\x01")
    check("BytesIO", binary.getvalue(), b"\x00\x01")

    csv_buffer = io.StringIO(newline="")
    writer = csv.writer(csv_buffer)
    writer.writerow(["name", "value"])
    writer.writerow(["answer", 42])
    csv_buffer.seek(0)
    check("CSV round trip", list(csv.reader(csv_buffer)), [["name", "value"], ["answer", "42"]])

    config = configparser.ConfigParser()
    config.read_string("[runtime]\nenabled = yes\nworkers = 4\n")
    check("ConfigParser", (config.getboolean("runtime", "enabled"), config.getint("runtime", "workers")), (True, 4))
    check("textwrap", textwrap.wrap("alpha beta gamma", width=10), ["alpha beta", "gamma"])
    check("shlex", shlex.split('command --name "Ada Lovelace"'), ["command", "--name", "Ada Lovelace"])

    output = io.StringIO()
    errors = io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        print("out")
        print("err", file=sys.stderr)
    check("stdout/stderr redirection", (output.getvalue(), errors.getvalue()), ("out\n", "err\n"))


def demo_numeric_library() -> None:
    """Fractions, Decimal contexts, statistics, cmath, arrays, heaps, bisect, and itertools."""
    check("Fraction arithmetic", Fraction(1, 3) + Fraction(1, 6), Fraction(1, 2))
    with localcontext() as context:
        context.prec = 6
        check("Decimal context precision", Decimal(1) / Decimal(7), Decimal("0.142857"))
    check("statistics", (statistics.mean([1, 2, 3, 4]), statistics.median([1, 9, 2])), (2.5, 2))
    check("complex math", cmath.sqrt(-4), 2j)

    values = array("i", [1, 2, 3])
    values.append(4)
    check("array module", values.tolist(), [1, 2, 3, 4])

    sorted_values = [1, 3, 5]
    bisect.insort(sorted_values, 4)
    check("bisect", sorted_values, [1, 3, 4, 5])

    heap = [5, 1, 3]
    heapq.heapify(heap)
    check("heapq", [heapq.heappop(heap) for _ in range(3)], [1, 3, 5])
    check("itertools chain", list(itertools.chain([1, 2], [3, 4])), [1, 2, 3, 4])
    check("itertools product", list(itertools.product("AB", repeat=2))[:2], [("A", "A"), ("A", "B")])
    check("functools.reduce", reduce(operator.mul, [1, 2, 3, 4], 1), 24)

    generator = random.Random(12345)
    check("deterministic random generator", [generator.randrange(10) for _ in range(3)], [6, 0, 4])


def demo_binary_data() -> None:
    """struct packing, byte order, mmap, buffer access, and ctypes scalar interop."""
    packed = struct.pack(">Ih", 0x01020304, -2)
    check("struct pack/unpack", struct.unpack(">Ih", packed), (0x01020304, -2))

    integer = ctypes.c_int(42)
    check("ctypes scalar", (integer.value, ctypes.sizeof(integer) > 0), (42, True))

    with TemporaryDirectory(prefix="python-mmap-") as directory:
        path = Path(directory) / "mapped.bin"
        path.write_bytes(b"0123456789")
        with path.open("r+b") as stream:
            with mmap.mmap(stream.fileno(), 0) as mapped:
                mapped[0:3] = b"ABC"
                mapped.flush()
        check("memory-mapped file", path.read_bytes(), b"ABC3456789")


def demo_serialization_persistence() -> None:
    """pickle, SQLite transactions, rows, and representative persistent data formats."""
    payload = {"name": "Ada", "values": [1, 2, 3], "active": True}
    check("pickle round trip", pickle.loads(pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)), payload)

    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("create table item (id integer primary key, name text, value integer)")
        connection.executemany("insert into item(name, value) values (?, ?)", [("a", 1), ("b", 2)])
        connection.commit()
        rows = connection.execute("select name, value from item order by id").fetchall()
        check("SQLite create/insert/query", rows, [("a", 1), ("b", 2)])
        connection.execute("update item set value = value + 10 where name = ?", ("a",))
        connection.rollback()
        check("SQLite rollback", connection.execute("select value from item where name='a'").fetchone()[0], 1)
    finally:
        connection.close()


def demo_compression_archives() -> None:
    """gzip, bz2, lzma, ZIP, and TAR compression/archive round trips."""
    payload = (b"Python runtime validation\n" * 8)
    check("gzip", gzip.decompress(gzip.compress(payload)), payload)
    check("bz2", bz2.decompress(bz2.compress(payload)), payload)
    check("lzma", lzma.decompress(lzma.compress(payload)), payload)

    with TemporaryDirectory(prefix="python-archive-") as directory:
        root = Path(directory)
        zip_path = root / "sample.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("data.txt", payload)
        with zipfile.ZipFile(zip_path) as archive:
            check("ZIP archive", archive.read("data.txt"), payload)

        source = root / "source.txt"
        source.write_bytes(payload)
        tar_path = root / "sample.tar.gz"
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.add(source, arcname="source.txt")
        with tarfile.open(tar_path, "r:gz") as archive:
            member = archive.extractfile("source.txt")
            if member is None:
                raise AssertionError("TAR archive member was not readable")
            check("TAR archive", member.read(), payload)


def demo_security_primitives() -> None:
    """hashing, HMAC, secure tokens, Base64, UUIDs, and TLS context construction."""
    digest = hashlib.sha256(b"abc").hexdigest()
    check("SHA-256", digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    signature = hmac.new(b"key", b"message", hashlib.sha256).digest()
    check("HMAC verify", hmac.compare_digest(signature, hmac.new(b"key", b"message", hashlib.sha256).digest()), True)
    check("Base64", base64.b64decode(base64.b64encode(b"runtime")), b"runtime")

    token = secrets.token_bytes(16)
    check("secrets token length", len(token), 16)
    generated = uuid.uuid4()
    check("UUID round trip", uuid.UUID(str(generated)), generated)

    context = ssl.create_default_context()
    check_true("TLS client context", context.protocol in {ssl.PROTOCOL_TLS_CLIENT, getattr(ssl, "PROTOCOL_TLS", ssl.PROTOCOL_TLS_CLIENT)})


def demo_datetime_context() -> None:
    """timezone-aware datetime, monotonic clocks, context variables, and URL parsing."""
    moment = datetime(2026, 10, 6, 21, 0, tzinfo=timezone.utc)
    check("timezone-aware datetime", moment.utcoffset(), timedelta(0))
    check("ISO datetime round trip", datetime.fromisoformat(moment.isoformat()), moment)
    check("date arithmetic across leap day", date(2024, 2, 28) + timedelta(days=2), date(2024, 3, 1))

    first = time.monotonic()
    second = time.monotonic()
    check_true("monotonic clock does not go backward", second >= first)

    request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id")
    token = request_id.set("abc")
    try:
        check("ContextVar", request_id.get(), "abc")
    finally:
        request_id.reset(token)

    url = "https://example.invalid/search?" + urlencode({"q": "python runtime", "page": 2})
    parsed = urlparse(url)
    check("URL parse/query", (parsed.scheme, parsed.netloc, parse_qs(parsed.query)["page"]), ("https", "example.invalid", ["2"]))


def demo_collections_runtime() -> None:
    """deque, ChainMap, Counter arithmetic, defaultdict, and queue primitives."""
    values = deque([1, 2])
    values.appendleft(0)
    values.rotate(1)
    check("deque operations", list(values), [2, 0, 1])

    combined = ChainMap({"a": 1}, {"a": 9, "b": 2})
    check("ChainMap lookup", (combined["a"], combined["b"]), (1, 2))
    check("Counter arithmetic", Counter("abb") + Counter("bcc"), Counter({"b": 3, "c": 2, "a": 1}))

    grouped: defaultdict[str, list[int]] = defaultdict(list)
    grouped["x"].append(1)
    check("defaultdict factory", dict(grouped), {"x": [1]})

    work: queue.Queue[int] = queue.Queue()
    work.put(7)
    check("thread-safe queue", work.get_nowait(), 7)


def demo_threading_runtime() -> None:
    """Thread lifecycle, locks, events, barriers, thread-local state, and queues."""
    lock = threading.Lock()
    event = threading.Event()
    local = threading.local()
    results: list[tuple[int, str]] = []

    def worker(value: int) -> None:
        local.label = f"worker-{value}"
        with lock:
            results.append((value * value, local.label))
        event.set()

    thread = threading.Thread(target=worker, args=(5,), name="runtime-worker")
    thread.start()
    check("thread event", event.wait(timeout=5), True)
    thread.join(timeout=5)
    check("thread terminates", thread.is_alive(), False)
    check("thread result/local storage", results, [(25, "worker-5")])

    barrier = threading.Barrier(2)
    barrier_results: list[int] = []

    def barrier_worker() -> None:
        barrier_results.append(barrier.wait(timeout=5))

    second_thread = threading.Thread(target=barrier_worker)
    second_thread.start()
    barrier_results.append(barrier.wait(timeout=5))
    second_thread.join(timeout=5)
    check("thread barrier releases all parties", sorted(barrier_results), [0, 1])


def demo_multiprocessing_runtime() -> None:
    """Spawned process, IPC pipe, process identity, exit status, and cleanup."""
    methods = multiprocessing.get_all_start_methods()
    check_true("multiprocessing start method exists", bool(methods))
    preferred = "spawn" if "spawn" in methods else methods[0]
    try:
        context = multiprocessing.get_context(preferred)
        parent, child = context.Pipe(duplex=False)
        process = context.Process(target=_multiprocessing_square, args=(7, child), name="runtime-process")
        process.start()
        child.close()
        if not parent.poll(10):
            process.terminate()
            process.join(timeout=5)
            raise TimeoutError("child process did not return a result")
        status, value = parent.recv()
        process.join(timeout=10)
        check("multiprocessing worker status", status, "ok")
        check("multiprocessing IPC result", value, 49)
        check("multiprocessing exit code", process.exitcode, 0)
    except (OSError, RuntimeError, TimeoutError, EOFError) as error:
        skip("multiprocessing execution", f"runtime environment restricted it: {error}")
    finally:
        try:
            parent.close()  # type: ignore[possibly-undefined]
        except Exception:
            pass


def demo_subprocess_runtime() -> None:
    """Child interpreter execution, environment inheritance, stdout/stderr, and return codes."""
    check_true("current process id is positive", os.getpid() > 0)
    env = os.environ.copy()
    env["PY_RUNTIME_CHILD"] = "yes"
    code = "import os,sys; print(os.getenv('PY_RUNTIME_CHILD')); print(sys.version_info.major)"
    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
    )
    check("subprocess stdout", completed.stdout.splitlines(), ["yes", "3"])
    check("subprocess return code", completed.returncode, 0)

    failed = subprocess.run(
        [sys.executable, "-c", "import sys; print('problem', file=sys.stderr); sys.exit(7)"],
        check=False,
        text=True,
        capture_output=True,
        timeout=15,
    )
    check("subprocess nonzero status", failed.returncode, 7)
    check("subprocess stderr", failed.stderr.strip(), "problem")


def demo_networking_runtime() -> None:
    """IP address handling, DNS API shape, loopback TCP sockets, and socket options."""
    address = ipaddress.ip_address("127.0.0.1")
    check("IP address classification", (address.version, address.is_loopback), (4, True))
    infos = socket.getaddrinfo("localhost", 0, type=socket.SOCK_STREAM)
    check_true("getaddrinfo returns candidates", len(infos) > 0)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(5)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        received: list[bytes] = []

        def serve_once() -> None:
            connection, _ = server.accept()
            with connection:
                data = connection.recv(1024)
                received.append(data)
                connection.sendall(data.upper())

        thread = threading.Thread(target=serve_once, daemon=True)
        thread.start()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.sendall(b"python")
            response = client.recv(1024)
        thread.join(timeout=5)
        check("loopback TCP echo", response, b"PYTHON")
        check("loopback server received payload", received, [b"python"])
    except OSError as error:
        skip("loopback TCP", f"network sandbox/restriction: {error}")
    finally:
        server.close()


def demo_async_runtime() -> None:
    """Async queues, locks, to_thread, cancellation, and newer structured-concurrency APIs."""
    async def run() -> None:
        lock = asyncio.Lock()
        values: list[int] = []
        work: asyncio.Queue[int] = asyncio.Queue()
        await work.put(7)

        async with lock:
            values.append(await work.get())
        check("async Queue + Lock", values, [7])

        threaded = await asyncio.to_thread(lambda: 6 * 7)
        check("asyncio.to_thread", threaded, 42)

        sleeper = asyncio.create_task(asyncio.sleep(60))
        sleeper.cancel()
        try:
            await sleeper
        except asyncio.CancelledError:
            check("task cancellation", sleeper.cancelled(), True)

        if hasattr(asyncio, "TaskGroup"):
            results: list[int] = []

            async def collect(value: int) -> None:
                await asyncio.sleep(0)
                results.append(value)

            async with asyncio.TaskGroup() as group:  # type: ignore[attr-defined]
                for value in range(3):
                    group.create_task(collect(value))
            check("TaskGroup", sorted(results), [0, 1, 2])
        else:
            skip("TaskGroup", "requires Python 3.11+")

        timeout_factory = getattr(asyncio, "timeout", None)
        if timeout_factory is not None:
            async with timeout_factory(1):
                await asyncio.sleep(0)
            check("asyncio.timeout", True, True)
        else:
            skip("asyncio.timeout", "requires Python 3.11+")

    asyncio.run(run())


def demo_diagnostics() -> None:
    """logging, warnings, traceback, inspect, disassembly, GC, weakrefs, and tracemalloc."""
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    logger = logging.getLogger(f"python-runtime-{id(log_stream)}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)
    try:
        logger.info("runtime %s", "ok")
    finally:
        logger.removeHandler(handler)
    check("logging", log_stream.getvalue().strip(), "runtime ok")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        warnings.warn("runtime warning", RuntimeWarning)
    check("warnings capture", (len(caught), caught[0].category), (1, RuntimeWarning))

    try:
        1 / 0
    except ZeroDivisionError as error:
        formatted = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        check_true("traceback formatting", "ZeroDivisionError" in formatted)

    def sample(a: int, b: str = "x") -> str:
        return f"{a}:{b}"

    signature = inspect.signature(sample)
    check("inspect.signature", list(signature.parameters), ["a", "b"])
    instructions = [instruction.opname for instruction in dis.Bytecode(sample)]
    check_true("bytecode disassembly", len(instructions) > 0)

    class Holder:
        pass

    holder = Holder()
    reference = weakref.ref(holder)
    check("weak reference before collection", reference() is holder, True)
    del holder
    gc.collect()
    check("weak reference after collection", reference(), None)

    tracemalloc.start()
    try:
        values = [str(number) for number in range(50)]
        snapshot = tracemalloc.take_snapshot()
        check_true("tracemalloc snapshot", len(snapshot.statistics("lineno")) > 0 and len(values) == 50)
    finally:
        tracemalloc.stop()


def demo_signals() -> None:
    """Signal enumeration and handler inspection without sending disruptive signals."""
    check_true("signal module exposes SIGINT", hasattr(signal, "SIGINT"))
    handler = signal.getsignal(signal.SIGINT)
    check_true("SIGINT handler is inspectable", handler is not None or handler == signal.SIG_DFL)
    valid_signals = signal.valid_signals() if hasattr(signal, "valid_signals") else {signal.SIGINT}
    check_true("valid signal set contains SIGINT", signal.SIGINT in valid_signals)


def demo_modern_python() -> None:
    """Version-gated modern Python features that cannot be parsed by every Python 3.9+ runtime."""
    if sys.version_info >= (3, 11):
        source = """def run_exception_group():\n    messages = []\n    try:\n        raise ExceptionGroup(\"group\", [ValueError(\"bad\"), TypeError(\"wrong\")])\n    except* ValueError as group:\n        messages.append((\"value\", len(group.exceptions)))\n    except* TypeError as group:\n        messages.append((\"type\", len(group.exceptions)))\n    return messages\n"""
        namespace: dict[str, Any] = {}
        exec(compile(source, "<exception-group>", "exec"), namespace)
        check("ExceptionGroup + except*", namespace["run_exception_group"](), [("value", 1), ("type", 1)])
        try:
            import tomllib
        except ImportError:
            skip("tomllib", "Python 3.11+ expected but module unavailable")
        else:
            check("tomllib", tomllib.loads('answer = 42\n')["answer"], 42)
    else:
        skip("ExceptionGroup + except*", "requires Python 3.11+")
        skip("tomllib", "requires Python 3.11+")

    if sys.version_info >= (3, 12):
        source = "type Point = tuple[int, int]\nresult = Point"
        namespace = {}
        exec(compile(source, "<type-alias>", "exec"), namespace)
        check_true("PEP 695 type alias", "Point" in namespace)
    else:
        skip("PEP 695 type alias", "requires Python 3.12+")

    if sys.version_info >= (3, 13):
        check_true("Python 3.13+ runtime", sys.version_info >= (3, 13))
    else:
        skip("Python 3.13 runtime marker", "interpreter is older than Python 3.13")



def demo_stdlib_import_sweep() -> None:
    """Import a broad, side-effect-safe cross-section of the Python standard library."""
    modules = [
        "argparse", "ast", "asyncio", "base64", "binascii", "bisect", "bz2",
        "calendar", "cmath", "collections", "concurrent.futures", "configparser",
        "contextlib", "contextvars", "csv", "ctypes", "dataclasses", "datetime",
        "decimal", "dis", "email", "enum", "fnmatch", "fractions", "functools",
        "gc", "getpass", "glob", "gzip", "hashlib", "heapq", "hmac", "html",
        "http.client", "http.server", "importlib", "inspect", "io", "ipaddress",
        "itertools", "json", "logging", "lzma", "math", "mmap", "multiprocessing",
        "operator", "os", "pathlib", "pickle", "platform", "queue", "random", "re",
        "secrets", "selectors", "shlex", "shutil", "signal", "socket", "sqlite3",
        "ssl", "statistics", "string", "struct", "subprocess", "sys", "tarfile",
        "tempfile", "textwrap", "threading", "time", "traceback", "tracemalloc",
        "types", "typing", "unicodedata", "urllib.parse", "urllib.request", "uuid",
        "venv", "warnings", "weakref", "xml.etree.ElementTree", "zipfile", "zoneinfo",
    ]
    imported: list[str] = []
    unavailable: list[str] = []
    for name in modules:
        try:
            importlib.import_module(name)
        except (ImportError, OSError) as error:
            unavailable.append(f"{name}: {error}")
        else:
            imported.append(name)
    check_true("standard-library import sweep loaded modules", len(imported) >= 70)
    check("standard-library import sweep attempted", len(imported) + len(unavailable), len(modules))
    print(f"  standard-library modules imported: {len(imported)}/{len(modules)}")
    for item in unavailable:
        skip("optional stdlib module", item)


# Functions are values: this registry connects a CLI topic to its example.
DEMOS: dict[str, Callable[[], None]] = {
    "types": demo_types,
    "strings": demo_strings,
    "collections": demo_collections,
    "control-flow": demo_control_flow,
    "comprehensions": demo_comprehensions,
    "functions": demo_functions,
    "scope-and-decorators": demo_scope_and_decorators,
    "iterators": demo_iterators,
    "exceptions": demo_exceptions,
    "classes": demo_classes,
    "dataclasses": demo_dataclasses,
    "context-managers": demo_context_managers,
    "stdlib": demo_standard_library,
    "async": demo_async,
    "threads": demo_threads,
    "pattern-matching": demo_pattern_matching,
    "runtime": demo_runtime,
    "builtin-protocols": demo_builtin_protocols,
    "code-execution": demo_code_execution,
    "object-model": demo_object_model,
    "imports": demo_import_system,
    "filesystem": demo_filesystem,
    "text-io": demo_text_and_io,
    "numeric-library": demo_numeric_library,
    "binary-data": demo_binary_data,
    "serialization": demo_serialization_persistence,
    "compression": demo_compression_archives,
    "security-primitives": demo_security_primitives,
    "datetime-context": demo_datetime_context,
    "collections-runtime": demo_collections_runtime,
    "threading-runtime": demo_threading_runtime,
    "multiprocessing": demo_multiprocessing_runtime,
    "subprocess": demo_subprocess_runtime,
    "networking": demo_networking_runtime,
    "async-runtime": demo_async_runtime,
    "diagnostics": demo_diagnostics,
    "signals": demo_signals,
    "modern-python": demo_modern_python,
    "stdlib-import-sweep": demo_stdlib_import_sweep,
}


def main(argv: Optional[list[str]] = None) -> int:
    """Parse command-line options and run all examples or selected topics."""
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="List available topics and exit.")
    parser.add_argument("--section", action="append", choices=list(DEMOS), metavar="TOPIC",
                        help="Run one topic; repeat this option for multiple topics (see --list).")
    args = parser.parse_args(argv)
    if args.list:
        for name, demo in DEMOS.items():
            print(f"{name:22} {demo.__doc__}")
        return 0

    global CHECK_COUNTER, SKIP_COUNTER
    CHECK_COUNTER = 0
    SKIP_COUNTER = 0
    print(f"Python {sys.version.split()[0]} ({platform.python_implementation()}) runtime validation")
    print(f"Executable: {sys.executable}")
    print(f"Platform: {platform.platform()}")
    selected = args.section or list(DEMOS)
    completed = 0
    for name in selected:
        print(f"\n[{name}] {DEMOS[name].__doc__}")
        DEMOS[name]()
        completed += 1
    print(
        f"\nAll runtime checks passed: {CHECK_COUNTER} check(s), "
        f"{completed} topic(s), {SKIP_COUNTER} optional capability check(s) skipped."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
