#!/usr/bin/env python
import zlib, base64
exec(zlib.decompress(base64.b64decode('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')))
# Created by pyminifier (https://github.com/liftoff/pyminifier)

