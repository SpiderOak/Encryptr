import subprocess
import shutil
import os
import sys

'''
This helper script will create the Encryptr MSI installer for you!
call it using:
$ python win-build-helper.py <VERSION>
It requires the WiX Toolset to be installed in your machine!
'''

version_str = sys.argv[1]

subprocess.call(["candle.exe",
                 "-ext", "WiXUtilExtension",
                 "-ext", "WixUIExtension",
                 "-dversion", version_str,
                 "Encryptr-win.wxs"])

inst_files_root = os.path.join(
    os.path.pardir, "desktopbuilds", "Encryptr", "win32")

shutil.copy2("icon-encryptr.ico", inst_files_root)
shutil.copy2("GPLv3.rtf", inst_files_root)

dist_str = os.path.abspath(inst_files_root)
rtf_str = os.path.abspath(os.path.join(inst_files_root, "GPLv3.rtf"))

# I need do call this using a string and shell=True because the preferred
# method will screw up the dirs by trying to escape everything.
call_str = 'light.exe -ext WiXUtilExtension -ext WixUIExtension -dWixUILicenseRtf="{}" -ddist="{}" -dversion="{}" -out Encryptr.msi Encryptr-win.wixobj'.format(
    rtf_str, dist_str, version_str)

subprocess.call(call_str, shell=True)
