import subprocess
import shutil
import os

subprocess.call(["candle.exe",
                "-ext", "WiXUtilExtension",
                "-ext", "WixUIExtension",
                "Encryptr-win.wxs"])

inst_files_root = os.path.join(
    os.path.pardir, "desktopbuilds", "Encryptr", "win32")

shutil.copy2("icon-encryptr.ico", inst_files_root)
shutil.copy2("GPLv3.rtf", inst_files_root)

dist_str = os.path.abspath(inst_files_root)
rtf_str = os.path.abspath(os.path.join(inst_files_root, "GPLv3.rtf"))

call_str = 'light.exe -ext WiXUtilExtension -ext WixUIExtension -dWixUILicenseRtf="{}" -ddist="{}" -out Encryptr.msi Encryptr-win.wixobj'.format(rtf_str, dist_str)

print("*************************")
print(call_str)

subprocess.call(call_str, shell=True)
