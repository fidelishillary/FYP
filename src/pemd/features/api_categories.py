"""Reverse engineering-guided API capability groups (FR-05, RQ2).

Individual imported function names are easy to shuffle, but the *capabilities*
a binary needs (inject into another process, resolve APIs at run time, detect a
debugger, ...) are much harder to remove without changing its behaviour. These
groups turn imports into capability counts. Extend or trim them as the Ghidra
case study confirms or rejects each one, and record the reason in
configs/re_feature_review.yaml.

Names are stored without the trailing A/W (ANSI/Unicode) suffix and lower-cased.
"""

API_CATEGORIES: dict[str, set[str]] = {
    "process_injection": {
        "virtualallocex", "writeprocessmemory", "createremotethread", "createremotethreadex",
        "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc", "ntqueueapcthread",
        "setthreadcontext", "ntunmapviewofsection", "zwunmapviewofsection", "openprocess",
        "ntwritevirtualmemory", "ntmapviewofsection",
    },
    "dynamic_resolution": {
        "loadlibrary", "loadlibraryex", "getprocaddress", "ldrloaddll",
        "ldrgetprocedureaddress", "getmodulehandle", "getmodulehandleex",
    },
    "anti_debug": {
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "outputdebugstring", "ntsetinformationthread", "gettickcount", "gettickcount64",
        "queryperformancecounter",
    },
    "memory_protection": {
        "virtualprotect", "virtualprotectex", "virtualalloc", "ntprotectvirtualmemory",
        "ntallocatevirtualmemory",
    },
    "crypto": {
        "cryptacquirecontext", "cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptimportkey",
        "cryptderivekey", "cryptgenrandom", "bcryptencrypt", "bcryptdecrypt",
        "bcryptgeneratesymmetrickey", "cryptstringtobinary",
    },
    "network": {
        "internetopen", "internetopenurl", "internetconnect", "internetreadfile",
        "httpopenrequest", "httpsendrequest", "urldownloadtofile", "winhttpopen",
        "winhttpconnect", "winhttpsendrequest", "wsastartup", "socket", "connect", "send",
        "recv", "gethostbyname", "getaddrinfo",
    },
    "registry": {
        "regsetvalueex", "regsetvalue", "regcreatekeyex", "regcreatekey", "regopenkeyex",
        "regdeletekey", "regdeletevalue", "regenumkeyex",
    },
    "keylogging_hooks": {
        "setwindowshookex", "getasynckeystate", "getkeystate", "getkeyboardstate",
        "getforegroundwindow", "registerrawinputdevices", "getrawinputdata",
    },
    "process_execution": {
        "createprocess", "createprocessasuser", "shellexecute", "shellexecuteex", "winexec",
        "createservice", "startservice", "openscmanager",
    },
    "file_enumeration": {
        "findfirstfile", "findfirstfileex", "findnextfile", "movefileex", "movefile",
        "deletefile", "getlogicaldrives", "getdrivetype",
    },
    "privilege": {
        "adjusttokenprivileges", "openprocesstoken", "lookupprivilegevalue",
        "impersonateloggedonuser", "duplicatetokenex",
    },
    "screen_capture": {"bitblt", "getdc", "getwindowdc", "createcompatiblebitmap"},
}


def normalise_api(name: str) -> str:
    """Lower-case and strip a trailing ANSI/Unicode suffix (CreateProcessW -> createprocess)."""
    if len(name) > 2 and name[-1] in "AW" and name[-2].islower():
        name = name[:-1]
    return name.lower()
