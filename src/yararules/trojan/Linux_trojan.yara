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

rule Linux_trojan_7aed64c0 { 
     meta : 
		creation_date = "11/02/2025"
        fingerprint = "7E6AA3BA00CBE13F277645BCC0E84E48329C85271D6B371819E5AE43D2154E86"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // Koristis
        $b1 = { 4B 6F 72 69 73 74 69 73 }

        // PORT PACKETS
        $b2 = { 50 4F 52 54 20 50 41 43 4B 45 54 53 }

    condition : 
        all of them
}

rule Linux_trojan_d4d6ab9e { 
     meta : 
		creation_date = "11/02/2025"
        fingerprint = "8348C7893EE7FAED3D6CDA3E31809FBFE071D49C0BEFFA42F6A174517B4A8104"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // <host> <port>
        $b1 = { 3C 68 6F 73 74 3E 20 3C 70 6F 72 74 3E }

        // connect faild
        $b2 = { 63 6F 6E 6E 65 63 74 20 66 61 69 6C 64 }

    condition : 
        all of them
}

rule Linux_trojan_5eb69f3b { 
     meta : 
		creation_date = "11/02/2025"
        fingerprint = "B787E1C39CF4C5AAA7128FF4CA6A6055730FDBFD9A46610E3CEBC123794D372C"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // x.@
        $b1 = { 78 00 40 }

        // .@.8.
        $b2 = { 00 40 00 38 00 }

    condition : 
        filesize < 3KB 
        and all of them
}
