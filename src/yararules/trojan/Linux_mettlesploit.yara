rule Linux_mettlesploit_trojan_4eae9a20 {
    meta : 
		creation_date = "17/01/2025"
        fingerprint = "9C4FA5A472437EA545EA974A6B4EA01EAEEA1D5378C6AC0044419D714FC01526"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // mettlesploit
        $b1 = { 6D 65 74 74 6C 65 73 70 6C 6F 69 74 }

        // /mettle/mettle/src/main.c
        $b2 = { 2F 6D 65 74 74 6C 65 2F 6D 65 74 74 6C 65 2F 73 72 63 2F 6D 61 69 6E 2E 63 }

    condition : 
        all of them
}