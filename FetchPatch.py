import platform
import sys

PATCH_MAP = {
    (6, 0, 6002): { # Vista and Server 2008
        "build_max": 19999,
        "arch": {
            "x86": "",
            "x64": "",
        }
    },
    (6, 1, 7601): { # Windows 7
        "build_max": 23999,
        "arch": {
            "x86": "",
            "x64": "",
        }
    },
    (6, 3, 9600): { # Windows 8.1 and Server 2012 R2
        "build_max": 17499,
        "arch": {
            "x86": "",
            "x64": "",
        }
    },
    (10, 0, 10240): { # Windows 10
        "build_max": 17499,
        "arch": {
            "x86": "",
            "x64": ""
        }
    }
}

def GetPatchURL(OSVersion, build, arch):
    for (major, minor, build), patch_info in PATCH_MAP.items():
        if (major, minor, build) == OSVersion:
            if build <= patch_info["build_max"]:
                return patch_info["arch"].get(arch)
    return None

