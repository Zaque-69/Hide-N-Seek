rule Linux_trojan_mettlesploit_4eae9a20 {
    meta : 
		creation_date = "17/01/2025"
        fingerprint = "3326044B9299F1032F3E2E7F775A33B4F0D59596DAAAD0C90233195119FE8990"
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