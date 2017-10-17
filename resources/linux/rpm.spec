Name:           Encryptr
Version:        %{version}
Vendor:         SpiderOak, Inc.
Release:        1%{?dist}
Summary:        A free, open source password manager and e-wallet.

License:        GPLv3
Packager:       SpiderOak
URL:            https://www.encryptr.org/

%description
A free, open source password manager and e-wallet. Encryptr is simple and easy
to use. It stores your sensitive data like passwords, credit card data, PINs,
or access codes, in the cloud. However, because it was built on the
zero-knowledge Crypton framework, Encryptr ensures that only the user has the
ability to access or read the confidential information. Not the app's developers,
cloud storage provider, or any third party.

%files
/opt/Encryptr
/usr/bin/Encryptr
/usr/share/applications/encryptr.desktop
/usr/share/doc/encryptr/
/usr/share/pixmaps/Encryptr.png

%define _rpmdir %{outdir}
%define __requires_exclude libudev.so.0

%post  
if [ -f /usr/lib/libudev.so.1 ]
then
ln -sf /usr/lib/libudev.so.1 /opt/Encryptr/libudev.so.0
fi
if [ -f /usr/lib64/libudev.so.1 ]
then
ln -sf /usr/lib64/libudev.so.1 /opt/Encryptr/libudev.so.0
fi

%preun
rm -rf /opt/Encryptr/libudev.so.0
