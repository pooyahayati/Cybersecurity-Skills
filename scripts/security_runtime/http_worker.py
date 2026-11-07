"""Private bounded acquisition worker. No token in process arguments or output."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_runtime.common import fields, integer, parse, require
from security_runtime.sources import Transport


def main():
    try:
        value = parse(sys.stdin.buffer.read(8193), 8192)
        fields(value, {"url", "limit", "asset", "token"})
        integer(value["limit"], 0, 512 * 1024 * 1024)
        require(type(value["asset"]) is bool, "invalid asset selection")
        code, content = Transport(value["token"]).get(value["url"], value["limit"], asset=value["asset"])
        sys.stdout.buffer.write(str(code).encode("ascii") + b"\n" + content)
        return 0
    except Exception:
        # Exceptions can contain signed redirect URLs; never emit them.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
