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