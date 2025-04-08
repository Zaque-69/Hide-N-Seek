rule Linux_itssoeasy_ransomware_bddc5a26 { 
    meta : 
		creation_date = "08/04/2024"
        github = "https://github.com/Zaque-69"
        fingerprint = "FCDC5532C83702E0E2DF358B546A5142E4283BEED3646A7C480AA6DDD72EFC63"
        sample = "https://bazaar.abuse.ch/download/bddc5a2605d4d8adff58e52f83000f536a64b84815f088e5ecce842a0ac8493c/"
        os = "Linux"

    strings : 
        
        // /usr/lib/go-1.17
        $b1 = { 2F 75 73 72 2F 6C 69 62 2F 67 6F 2D 31 2E 31 37 }

        // main.encryptData.func1
        $b2 = { 6D 61 69 6E 2E 65 6E 63 72 79 70 74 44 61 74 61 2E 66 75 6E 63 31 }

    condition : 
        filesize > 4MB
        and filesize < 6MB
        and all of them
}

rule Linux_itssoeasy_ramsomware_d2fc711b { 
    meta : 
		creation_date = "08/04/2024"
        github = "https://github.com/Zaque-69"
        fingerprint = "151AF44E98AEDE501B82A33AFD9C1F045055885625939C4F03E4AC3A1A659413"
        sample = "https://bazaar.abuse.ch/download/d2fc711b6ed6ff9f0a13cad6f1ed7c6d7cb2b0d4c5eb4a84f75d3a319befea8c/"
        os = "Linux"

    strings : 

        // 192.168.56.109
        $b1 = { 31 39 32 2E 31 36 38 2E 35 36 2E 31 30 39 }

        // otherwise your data 
        $b2 = { 6F 74 68 65 72 77 69 73 65 20 79 6F 75 72 20 64 61 74 61 20 }

        // will be irreversibly encrypted
        $b3 = { 77 69 6C 6C 20 62 65 20 69 72 72 65 76 65 72 73 69 62 6C 79 20 65 6E 63 72 79 70 74 65 64 }

    condition : 
        filesize > 20KB
        and filesize < 100KB
        and all of them
}