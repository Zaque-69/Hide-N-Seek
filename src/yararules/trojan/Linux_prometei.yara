rule Linux_prometei_abuse_ch {
    meta : 
		creation_date = "10/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "04FDF08E2BA9BA5538B69FF14AE59D671779447CE6C1C2C9454B4B055FEFF4D2"
        sample = "https://bazaar.abuse.ch/user/1/"
        os = "Linux"

    strings : 

        // "config":1
        $b1 = { 22 63 6F 6E 66 69 67 22 3A 31 }

        // "enckey"
        $b2 = { 22 65 6E 63 6B 65 79 22 }

        // ND7L5MmMXPNvnyyOBK3CFu4o
        $k1 = { 4E 44 37 4C 35 4D 6D 4D 58 50 4E 76 6E 79 79 4F 42 4B 33 43 46 75 34 6F }

        // fz/RB7NpZ26i1bFnEodrkjQ=
        $k2 = { 66 7A 2F 52 42 37 4E 70 5A 32 36 69 31 62 46 6E 45 6F 64 72 6B 6A 51 3D }

        // qFV5CTXcYPkCCJRC5QX8FJwl
        $k3 = { 71 46 56 35 43 54 58 63 59 50 6B 43 43 4A 52 43 35 51 58 38 46 4A 77 6C }

        // JXmImOMSqqZ6vK/Qd4cFbrs=
        $k4 = { 4A 58 6D 49 6D 4F 4D 53 71 71 5A 36 76 4B 2F 51 64 34 63 46 62 72 73 3D }

        // jJ4QdwoGcrmOt6mXCRoOxx+V
        $k5 = { 6A 4A 34 51 64 77 6F 47 63 72 6D 4F 74 36 6D 58 43 52 6F 4F 78 78 2B 56 }

        // 4cJ3hwF/cadwRAJbY/HM2Tc=
        $k6 = { 34 63 4A 33 68 77 46 2F 63 61 64 77 52 41 4A 62 59 2F 48 4D 32 54 63 3D } 

    condition : 
        filesize < 1MB
        and all of ( $b* )
        and 2 of ( $k* )
}