#!/usr/bin/env python
import zlib, base64
exec(zlib.decompress(base64.b64decode('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')))
# Created by pyminifier (https://github.com/liftoff/pyminifier)

