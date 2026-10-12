#!/usr/bin/env python3
#
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
This script checks for git modules
"""

import subprocess
import sys

# Product gitlinks. PQClean lives in these two repos, not as pasted C.
ALLOWED_GITLINKS = {
    "src/crypto/mldsa44",
    "src/crypto/mldsa87",
}

def main():
    submodules_list = subprocess.check_output(['git', 'submodule', 'status', '--recursive'],
                                                text = True, encoding = 'utf8').rstrip('\n')
    unexpected = []
    for line in submodules_list.splitlines():
        if not line.strip():
            continue
        path = line.split()[1]
        if path not in ALLOWED_GITLINKS:
            unexpected.append(line)
    if unexpected:
        print("These submodules were found, delete them:\n", "\n".join(unexpected))
        sys.exit(1)
    sys.exit(0)

if __name__ == '__main__':
    main()
