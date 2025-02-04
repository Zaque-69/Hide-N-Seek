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

rule Linux_trojan_13847901 {
    meta : 
		creation_date = "03/02/2025"
        fingerprint = "EDB7B4D4624DDB3A92B1D8227535E0441FB76149EA319FBDBC018501962C727B"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // unhex
        $b1 = { 75 6E 68 65 78 }

        // 55505821 -> UPX!
        $b2 = { 35 35 35 30 35 38 32 31 }

    condition : 
        all of them
}

rule Linux_trojan_0d9a34fd {
    meta : 
		creation_date = "04/02/2025"
        fingerprint = "3B9CB1C24432E38709E749BA76F25221AC4EF375665AFBE680BA6CF64307B82E"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // 0iNBe
        $b1 = { 30 69 4E 42 65 }

    condition : 
        all of them
}

rule Linux_trojan_3b74d5dd {
    meta : 
		creation_date = "04/02/2025"
        fingerprint = ""
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // LSD!
        $b1 = { 4C 53 44 21 }

    condition : 
        all of them
}