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

rule Linux_trojan_2d8e89b1 {
    meta : 
		creation_date = "11/01/2025"
        fingerprint = "5C8423DC7E8CA25831454C88E56B0A21E0058DF907D497109C6C82E47B3EB24A"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // Shellcode Length: %d
        $b1 = { 53 68 65 6C 6C 63 6F 64 65 20 4C 65 6E 67 74 68 3A 20 25 64 }

    condition : 
        all of them
}

rule Linux_trojan_2da44d9d {
    meta : 
		creation_date = "11/01/2025"
        fingerprint = "65A4C254284CF4B940FD908ECC386086E005178CAB72FADC843D94C6E7E5ABF9"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // Error in dlsym: %s
        $b1 = { 45 72 72 6F 72 20 69 6E 20 64 6C 73 79 6D 3A 20 25 73 }

    condition : 
        all of them
}