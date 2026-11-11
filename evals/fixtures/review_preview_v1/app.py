"""Tool-owned illustrative input, never run by the static preview."""


def trivial():
    return 1


class Router:
    async def handle(self):
        first = 1
        second = 2
        third = 3
        fourth = 4
        return first + second + third + fourth


def collect():
    records = []
    for value in range(3):
        records.append(value)
    return records
