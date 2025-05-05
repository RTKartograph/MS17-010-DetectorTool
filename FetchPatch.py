import os
import requests

PATCH_MAP = {
    (6, 0, 6002): { # Vista
        "build_max": 19999,
        "arch": {
            "x86": "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-x86_13e9b3d77ba5599764c296075a796c16a85c745c.msu",
            "x64": "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-x64_6a186ba2b2b98b2144b50f88baf33a5fa53b5d76.msu",
        }
    },
    (6, 1, 7601): { # Windows 7
        "build_max": 23999,
        "arch": {
            "x86": "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x86_6bb04d3971bb58ae4bac44219e7169812914df3f.msu",
            "x64": "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3.msu",
        }
    },
    (6, 3, 9600): { # Windows 8 / 8.1
        "build_max": 17499,
        "arch": {
            "x86": "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x86_e118939b397bc983971c88d9c9ecc8cbec471b05.msu",
            "x64": "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x64_5b24b9ca5a123a844ed793e0f2be974148520349.msu",
        }
    },
    (10, 0, 10240): { # Windows 10
        "build_max": 17499,
        "arch": {
            "x86": "N/A",
            "x64": "N/A" # Update your pc if you have windows 10 PLEASE
        }
    }
}

def GetPatchURL(OSVersion, build, arch):
    for (major, minor, build), patch_info in PATCH_MAP.items():
        if (major, minor, build) == OSVersion:
            if build <= patch_info["build_max"]:
                return patch_info["arch"].get(arch)
    return None

def DownloadPatch(url, filename="patch.msu"):
    patch = requests.get(url, stream=True)
    if patch.status_code(200):
        with open(filename, "wb") as f:
            for chunk in patch.iter_content(1024):
                f.write(chunk)
        print(f"Downloaded patch to {filename}")
        return filename
    else:
        print("Download failed.")
        return None

def RunPatch(filename):
    os.system(f"wusa {filename} /quiet /norestart")