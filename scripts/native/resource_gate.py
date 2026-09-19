#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Conservative resource admission for the shared native macOS f1 tier."""
import re
import shutil
import subprocess
import sys
import time

def main():
    for _ in range(4):
        swap = subprocess.check_output(['sysctl','-n','vm.swapusage'],text=True,timeout=10)
        match = re.search(r'used = ([\d.]+)([MG])',swap)
        if not match:
            print('RESOURCE unknown swap format; no build admitted')
            return 1
        used = float(match[1]) / (1024 if match[2] == 'M' else 1)
        count = subprocess.run(['pgrep','-x','rustc'],capture_output=True,text=True,timeout=10)
        if count.returncode not in (0,1):
            return 1
        rustc = len(count.stdout.splitlines())
        root = shutil.disk_usage('/').free / 1024**3
        volume = shutil.disk_usage('/Volumes/f1dev').free / 1024**3
        print(f'RESOURCE swap_GiB={used:.2f} rustc={rustc} root_GiB={root:.1f} f1dev_GiB={volume:.1f}',flush=True)
        if used <= 4 and rustc <= 8 and root >= 80 and volume >= 120:
            return 0
        print('RESOURCE backing off 300 seconds; no heavy command started',flush=True)
        time.sleep(300)
    return 1

if __name__ == '__main__':
    sys.exit(main())
