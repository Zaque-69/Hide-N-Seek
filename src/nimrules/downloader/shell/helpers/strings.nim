proc suspiciousCommandsDownloaderShell * () : seq[string] = 
    @[
        "WTF",
        "rm $0",
        "kr_cert",
        "android",
        "busybox",
        "cd /root",
        "chmod 777",
        "rm -rf .f",
        "/bins/parm",
        "cd /var/run",
        "rm lol.mips",
        "jackmymipsel",
        "chmod 777 parc",
        "chmod 777 parm",
        "chmod 777 parm5",
        "chmod 777 parm6",
        "chmod 777 psh4",
        "chmod 777 pmips",
        "rm -rf skid.mips",
        "/tmp/.a && cd /tmp;",
        "/dev/.a && cd /dev;",
        "/home/.a && cd /home;",
        "/dev/shm/.a && cd /dev/shm;",
        "/var/tmp/.a && cd /var/tmp;"
    ]

proc suspiciousIPCombinationDownloaderShell * (ip : string) : seq[string] =
    @[
        "wget " & ip,
        "wget -q" & ip,
        "curl -O " & ip,
        "wget http://" & ip,
        "http://" & ip & '/',
        "curl -O http://" & ip,
        ]