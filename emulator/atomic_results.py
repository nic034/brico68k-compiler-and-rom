"""Crash-safe JSON result publication for the Neo Geo emulator regression bench."""
import json
import os
import tempfile
from pathlib import Path


def write_results(path, results):
    """Publish a complete JSON result, leaving an existing file intact on failure."""
    target = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=str(target.parent),
                                         prefix='.' + target.name + '.', suffix='.tmp',
                                         delete=False) as stream:
            temporary = stream.name
            json.dump(results, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
