# Python EXE Launcher

This is a desktop launcher for users.

Flow:
1. User opens EXE
2. Enters `username` + `password` created in Admin `EXE Users` tab
3. EXE collects HWID + IP automatically
4. EXE calls `POST /api/exe/login`
5. Success shows loading animation and opens main app URL

## Run as script

```bat
python launcher.py
```

## Build EXE

```bat
build_exe.bat
```

Output EXE:

```text
python-client\dist\CloudXLauncher.exe
```

## Config

- Default API base: `http://localhost:5000`
- Override with env var:

```bat
set EXE_API_BASE=https://your-domain.com
CloudXLauncher.exe
```
