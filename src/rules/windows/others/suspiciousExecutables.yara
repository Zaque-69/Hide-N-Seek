rule suspicious_executables {
    strings:
        $c1 = "cmd.exe" ascii wide
        $c2 = "che.exe" ascii wide
        $c3 = "kdl.exe" ascii wide
        $c4 = "taskdl.exe" ascii wide
        $c5 = "taskse.exe" ascii wide
        $c6 = "mssecsvc.exe" ascii wide
        $c7 = "msiexec.exe" ascii wide
        $c8 = "explorer.exe" ascii wide
        $c9 = "LOGON.exe" ascii wide
        $c10 = "Project1.exe" ascii wide
    condition:
        any of them

}