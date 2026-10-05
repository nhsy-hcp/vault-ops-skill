#!/bin/bash
# Stage this case's own fixtures/ instead of the shared set.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$here/../fixtures/stage.sh" "$here/fixtures"
