"""Hand-Python baseline for fib.capa. Idiomatic recursive Fibonacci.
Measured by benchmarks/runner.py against the transpiled Capa output.
"""


def fib(n: int) -> int:
    if n < 2:
        return n
    return fib(n - 1) + fib(n - 2)


def workload() -> int:
    return fib(25)
