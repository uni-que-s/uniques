#!/usr/bin/env bash
# Fetch the official NIST Juliet Java 1.3 test suite and extract only the two
# crypto CWE directories used by this benchmark. The 73 MB archive is intentionally
# NOT vendored in the repo — its provenance stays with NIST.
set -euo pipefail
cd "$(dirname "$0")"

URL="https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip"

echo "Downloading official NIST Juliet Java 1.3 (~73 MB) from samate.nist.gov ..."
curl -fSL -o juliet-java.zip "$URL"

echo "Extracting CWE-327 (broken/risky crypto) + CWE-328 (reversible one-way hash) ..."
rm -rf juliet-java
unzip -q -o juliet-java.zip \
  '*/CWE327_Use_Broken_Crypto/*' \
  '*/CWE328_Reversible_One_Way_Hash/*' \
  -d juliet-java

echo "Done. Now run:  node score.mjs"
