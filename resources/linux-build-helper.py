#!/usr/bin/env python

"""
Helper script to build DEB and RPM installers for Encryptr!

Usage:

python linux-build-helper.py VERSION ARCH BUILD_FILES

VERSION is the Encryptr version we will set in the installers (e.g., 2.0.0)
ARCH is either amd64 or i386, and defines the target arch of the installers.
BUILD_FILES points to the root of the files that will be included in the app.
In a normal build process, you normally want this to be either
../desktopbuilds/Encryptr/linux64/ or ../desktopbuilds/Encryptr/linux86/

Example usage:

python linux-build-helper.py 2.0.0 amd64 ../desktopbuilds/Encryptr/linux64/
"""

import subprocess
import glob
import shutil
import os
import sys
import fileinput

version_str = sys.argv[1]
arch_str = sys.argv[2]
assert(arch_str in ["amd64", "i386"])
build_files = sys.argv[3]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def replace_str_in_file(file_path, source_str, replace_str):
    """Replace all appearences of source_str for replace_str in
    the file from file_path.
    """
    # In Python 2.X FileInput cannot be used as context manager
    f = fileinput.FileInput(file_path, inplace=True)
    for line in f:
        # replace the string on each line of the file
        # we use the trailing comma to avoid double line jumps,
        # because each line already contains a \n char
        print line.replace(source_str, replace_str),
    f.close()


def place_version_strings(basedir, version):
    """Replace version strings in all files that need them."""
    target_files = [
        os.path.join(basedir, "DEBIAN", "control"),
        os.path.join(basedir, "usr", "share",
                     "applications", "encryptr.desktop")
    ]
    for f in target_files:
        replace_str_in_file(f, "INSERT_VERSION_HERE", version)


def place_arch_strings(basedir, arch):
    """Replace arch strings (i386/amd64) in all files that need them."""
    replace_str_in_file(os.path.join(basedir, "DEBIAN", "control"),
                        "INSERT_ARCH_HERE", arch)


def place_build_files(basedir, build_dir):
    """Place built files in the required directories."""
    dest_dir = os.path.join(basedir, "opt", "Encryptr")
    for filename in glob.glob(os.path.join(build_dir, '*')):
        if os.path.isfile(filename):
            shutil.copy2(filename, dest_dir)
    # move main binary so that it's called by our entrypoint script
    shutil.move(os.path.join(dest_dir, "Encryptr"),
                os.path.join(dest_dir, "encryptr-bin"))


def create_deb(basedir, out_path):
    """Create the DEB installer from basedir. Place DEB in out_path."""
    subprocess.check_call([
        "fakeroot",
        "dpkg-deb",
        "-b",
        basedir,
        out_path,
    ],
    )


def create_rpm(version, arch, rpm_spec, dist_root, out_dir):
    arch_str = arch if arch == "i386" else "x86_64"
    subprocess.check_call([
        "rpmbuild",
        "-bb",
        "-D", "version " + version,
        "--buildroot", dist_root,
        "-D", "outdir " + out_dir,
        "--target", arch_str,
        rpm_spec
    ])


def setup_dirs(basedir, resources):
    """Create the installer tree."""
    # remove the workdir if it exists, and create an empty one
    shutil.rmtree(basedir, ignore_errors=True)
    os.makedirs(basedir)
    # copy all linux/usr/ folder (contains helper scripts, entrypoint, etc)
    shutil.copytree(os.path.join(resources, "usr"),
                    os.path.join(basedir, "usr"))
    # copy maintenance scripts
    shutil.copytree(os.path.join(resources, "DEBIAN"),
                    os.path.join(basedir, "DEBIAN"))
    os.makedirs(os.path.join(basedir, "opt", "Encryptr"))


def clean_deb_files(basedir):
    shutil.rmtree(os.path.join(basedir, "DEBIAN"))

dist_root = os.path.join(BASE_DIR, "linux_inst")
res_dir = os.path.join(BASE_DIR, "linux")
setup_dirs(dist_root, res_dir)
place_version_strings(dist_root, version_str)
place_arch_strings(dist_root, arch_str)
place_build_files(dist_root, build_files)
create_deb(dist_root, BASE_DIR)
clean_deb_files(dist_root)
create_rpm(version_str, arch_str, os.path.join(
    res_dir, "rpm.spec"), dist_root, BASE_DIR)
