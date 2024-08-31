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

rule DLLS_used{
    strings:
        $c1 = "KERNEL32.dll" ascii wide
	$c2 = "USER32.dll" ascii wide
	$c3 = "ADVAPI32.dll" ascii wide
	$c4 = "NETAPI32.dll" ascii wide
	$c5 = "USERENV.dll" ascii wide
	$c6 = "WININET.dll" ascii wide
	$c7 = "mscoree.dll" ascii wide
        $c8 = "WSOCK.dll" ascii wide 		//a critical system file in Windows that is responsible for managing Winsock (Windows Sockets) functionality
	$c9 = "WINMM.dll" ascii wide 		//a dynamic link library file that is an integral part of the Windows operating system	
        $c10 = "shell32.dll" ascii wide         //a crucial file in the Windows operating system that plays a significant role in providing the graphical user interface (GUI)


    condition:
        any of them

}

rule suspicious_URLs {
    strings:
        $c1 = "http://wallup.net" ascii wide
		
    condition:
        any of them

}
