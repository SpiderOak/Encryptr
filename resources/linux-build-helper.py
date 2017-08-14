import subprocess
import glob
import shutil
import os
import sys
import fileinput

version_str = sys.argv[1]
arch_str = sys.argv[2]
build_files = sys.argv[3]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def replace_str_in_file(file_path, source_str, replace_str):
    """Replace all appearences of source_str for replace_str in
    the file from file_path.
    """
    with fileinput.FileInput(file_path, inplace=True) as file:
        for line in file:
            # replace the string on each line of the file
            # end='' prevents this from writing double line ends
            # since each line already has a \n
            print(line.replace(source_str, replace_str), end='')


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


def setup_dirs(basedir, resources):
    """Create the installer tree."""
    # remove ./debian_inst/ if it exists, and create an empty one
    shutil.rmtree(basedir, ignore_errors=True)
    os.makedirs(basedir)
    # copy all linux/usr/ folder (contains helper scripts, entrypoint, etc)
    shutil.copytree(os.path.join(resources, "usr"),
                    os.path.join(basedir, "usr"))
    # copy maintenance scripts
    shutil.copytree(os.path.join(resources, "DEBIAN"),
                    os.path.join(basedir, "DEBIAN"))
    os.makedirs(os.path.join(basedir, "opt", "Encryptr"))

deb_root = os.path.join(BASE_DIR, "debian_inst")
res_dir = os.path.join(BASE_DIR, "linux")
setup_dirs(deb_root, res_dir)
place_version_strings(deb_root, version_str)
place_arch_strings(deb_root, arch_str)
place_build_files(deb_root, build_files)

subprocess.check_call([
    "fakeroot",
    "dpkg-deb",
    "-b",
    deb_root,
    os.getcwd(),
],
)
