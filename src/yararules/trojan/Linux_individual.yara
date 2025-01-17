rule Linux_trojan_2f0b2160 {
    meta : 
		creation_date = "11/01/2025"
        fingerprint = "4921AF8AB1C0EC9D35E027519CDD8642B7335F0E72F28EAC21FEF62301B7600F"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // GenuineIntelAuthenticAMDCentaurHauls
        $b1 = { 47 65 6E 75 69 6E 65 49 6E 74 65 6C 41 75 74 68 65 6E 74 69 63 41 4D 44 43 65 6E 74 61 75 72 48 61 75 6C 73 }

    condition : 
        all of them
}