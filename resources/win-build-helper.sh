candle.exe -ext WiXUtilExtension -ext WixUIExtension Encryptr.wxs
light.exe  -ext WiXUtilExtension -ext WixUIExtension -dWixUILicenseRtf="C:\Encryptr\resources\GPLv3.rtf" -ddist="c:\Encryptr\desktopbuilds\Encryptr\win32" -out Encryptr.msi Encryptr.wixobj
