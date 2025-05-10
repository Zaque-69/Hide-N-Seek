rule Linux_generic_e157d5c7 {
    meta : 
		creation_date = "06/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "825A9A46870FF13626B8703AD7ACFC64B2C61E4792B6838419EEE3D543E38184"
        sample = "https://bazaar.abuse.ch/download/e157d5c74cf949af2105f513b93bc5f1e745c33d2e8e28aca333c52ec4d0ec11/"
        os = "Linux"

    strings : 

        // Backtrace: =========
        $b1 = { 42 61 63 6B 74 72 61 63 65 3A 20 3D 3D 3D 3D 3D 3D 3D 3D 3D }

        // corrupted double-linked
        $b2 = { 63 6F 72 72 75 70 74 65 64 20 64 6F 75 62 6C 65 2D 6C 69 6E 6B 65 64 }

        // ANSI_X3.4-1968//TRANSLIT
        $b3 = { 41 4E 53 49 5F 58 33 2E 34 2D 31 39 36 38 2F 2F 54 52 41 4E 53 4C 49 54 }

    condition : 
        filesize > 400KB
        and filesize < 600KB
        and all of them
}

rule Linux_generic_925f6496 {
    meta : 
		creation_date = "10/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "0320017FF3303F57CE138AEEB776BAE692C37AF364AFE4EB7F3EDB3BD0AA9463"
        sample = "https://bazaar.abuse.ch/download/925f649617743f0640bdfff4b6b664b9e12761b0e24bbb99ca72740545087ad2"
        os = "Linux"

    strings : 

        // 41F0BB2FA36AAA95c
        $b1 = { 34 31 46 30 42 42 32 46 41 33 36 41 41 41 39 35  }

        // Backtrace: =========
        $b2 = { 42 61 63 6B 74 72 61 63 65 3A 20 3D 3D 3D 3D 3D 3D 3D 3D 3D }

        // /usr/lib/locale/locale-archive
        $b3 = { 2F 75 73 72 2F 6C 69 62 2F 6C 6F 63 61 6C 65 2F 6C 6F 63 61 6C 65 2D 61 72 63 68 69 76 65 }

    condition : 
        filesize > 500KB
        and filesize < 1MB
        and all of them
}

rule Linux_generic_98bb38bb {
    meta : 
		creation_date = "10/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "BF8A98877261D22B68F1C7AA37ABA167A7E5A6F1302E572CF5DCE45CD69C0BD8"
        sample = "https://bazaar.abuse.ch/download/98bb38bbc72ffe81ffb14222742902e875627dd3b485b4ac8fbcc16cb4ec456c"
        os = "Linux"

    strings : 

        // killall minerd
        $b1 = { 6B 69 6C 6C 61 6C 6C 20 6D 69 6E 65 72 64  }

        // ktx-mipsel.killall
        $b2 = { 6B 74 78 2D 6D 69 70 73 65 6C 0A 6B 69 6C 6C 61 6C 6C }

        // --BEGIN PUBLIC KEY--
        $b3 = { 2D 2D 42 45 47 49 4E 20 50 55 42 4C 49 43 20 4B 45 59 2D 2D }

        // MIGfMA0GCSqGSIb3DQEB
        $b4 = { 4D 49 47 66 4D 41 30 47 43 53 71 47 53 49 62 33 44 51 45 42 }

        // Bucharest.RO.EU.Undernet.Org
        $b5 = { 42 75 63 68 61 72 65 73 74 2E 52 4F 2E 45 55 2E 55 6E 64 65 72 6E 65 74 2E 4F 72 67 }

    condition : 
        filesize < 50KB
        and 4 of them
}

rule Linux_generic_fa004327 {
    meta : 
		creation_date = "10/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "2395CE54EE4C289080EEC249C3C66DB463C8305FF8AAA03EC06B7872F568CC1F"
        sample = "https://bazaar.abuse.ch/download/fa0043270463a66947998bdba437dbe52ae94bac08211a7f7690ebdd8ec3fd8f"
        os = "Linux"

    strings : 

        // 45.136.244.44
        $b1 = { 34 35 2E 31 33 36 2E 32 34 34 2E 34 34 }

        // POST
        $b2 = { 50 4F 53 54 }

    condition : 
        filesize < 100KB
        and all of them
}

rule Linux_generic_2d8e89b1 {
    meta : 
		creation_date = "11/01/2025"
        update_date = "05/10/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "8E920F81400B959F27D31C3685A1EBBA2B1896EFE55943DC18F747ECB821C9D6"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/2d8e89b1febe64a6c35ec2fbbe1535bca4a0f4744f560e9737a17050e66cd6a6"
        os = "Linux"

    strings : 

        // Shellcode Length: %d
        $b1 = { 53 68 65 6C 6C 63 6F 64 65 20 4C 65 6E 67 74 68 3A 20 25 64 }

    condition : 
        all of them
}

rule Linux_generic_2da44d9d {
    meta : 
		creation_date = "11/01/2025"
        update_date = "05/10/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "EA64C32AA75D8889FE3B12CD416394E5EC8F43C5443AF1D24C2D3EE6846C3DBB"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/2da44d9d925078449fba3d1f8efd81fa9833e5e83d7da8d69a62427790c05741"
        os = "Linux"

    strings : 

        // Error in dlsym: %s
        $b1 = { 45 72 72 6F 72 20 69 6E 20 64 6C 73 79 6D 3A 20 25 73 }

    condition : 
        all of them
}