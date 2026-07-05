import sys
import types


magic_stub = types.ModuleType("magic")


def _from_buffer(_buffer, mime=True):
    if mime:
        return "application/pdf"
    return "PDF document"


magic_stub.from_buffer = _from_buffer
sys.modules.setdefault("magic", magic_stub)
