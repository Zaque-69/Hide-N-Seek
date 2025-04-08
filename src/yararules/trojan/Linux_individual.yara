rule Linux_trojan_2f0b2160 {
    meta : 
		creation_date = "11/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "5813B37417A67A0CA6EE973D01D1D51F6FAAD94479E7029ED3F54809D208BF3D"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/2f0b2160470e2253dc6a5c9cf950962c5999ee209d0eb0db237a4c630cb34e7a"
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
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "3B49392E8C7CB3177188D0EEFA7E9020CCB1BCD04F260BAEF8714332BFAABE9E"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/2d8e89b1febe64a6c35ec2fbbe1535bca4a0f4744f560e9737a17050e66cd6a6"
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
        update_date = "04/04/2025"
        fingerprint = "51FC2B732FD91C29842B71804F0633094693D2F4A4DE740CCA6DF7E358045691"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/2da44d9d925078449fba3d1f8efd81fa9833e5e83d7da8d69a62427790c05741"
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
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "60AFD6D963D8A87D5FEEF4BF6E12D3EF6041A0038EC744E0DE13FF5E96DC0150"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/1384790107a5f200cab9593a39d1c80136762b58d22d9b3f081c91d99e5d0376"
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
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "FDF7BF1A81C349E29F3066A3052C89C5FD115763E7C3513FFD0CF55E99E83EE8"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/0d9a34fd35ea6aa090c93f6f8310e111f9276bacbdf5f14e5f1f8c1dc7bf3ce5"
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
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "8F632ACC50E0F8EBFAD8A3A5A7EC3BFC613AADE6648BCF73F3B57478C9C10BCC"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/3b74d5ddd75f6713f2f04067ab585132a9b88c02cd7fa9391ee322966c61e390"
        os = "Linux"

    strings : 

        // LSD!
        $b1 = { 4C 53 44 21 }

    condition : 
        filesize > 300KB
        and all of them
}

rule Linux_trojan_Gonna_cry {
    meta :
		creation_date = "18/03/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "4090BC98269B913D96D89EA27B3EDE963ED89FFFD678CA2EE088467001DCAB9B"
        sample = "https://bazaar.abuse.ch/sample/f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac/"
        os = "Linux"

    strings :

        // Sup brother
        $b1 = { 53 75 70 20 62 72 6F 74 68 65 72 }

        // all your files below have been encrypted
        $b2 = { 61 6C 6C 20 79 6F 75 72 20 66 69 6C 65 73 20 62 65 6C 6F 77 20 68 61 76 65 20 62 65 65 6E 20 65 6E 63 72 79 70 74 65 64 }

        // cheers!
        $b3 = { 63 68 65 65 72 73 21 }

    condition :
        filesize > 10KB
        and filesize < 40KB
        and all of them
}

rule Linux_trojan_4cc1f6fc {
    meta : 
		creation_date = "01/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "D64A9BC132053DCC1FFD769D9BA2ADE1142805DDC9A89F2A6CA68D007750010D"
        sample = "https://bazaar.abuse.ch/download/4cc1f6fcf8afeda5c1529361ac6242777777c0c5fc8d8e32ebf6d49504633cf1/"
        os = "Linux"

    strings : 

        // :) must be a power of 2
        $b1 = { 3A 29 20 6D 75 73 74 20 62 65 20 61 20 70 6F 77 65 72 20 6F 66 20 32 }

        // golang.org
        $b2 = { 67 6F 6C 61 6E 67 2E 6F 72 67 }

        // C:/Users/Administrator/go/pkg/mod/github.com/!puerkito!bio
        $b3 = { 43 3A 2F 55 73 65 72 73 2F 41 64 6D 69 6E 69 73 74 72 61 74 6F 72 2F 67 6F 2F 70 6B 67 2F 6D 6F 64 2F 67 69 74 68 75 62 2E 63 6F 6D 2F 21 70 75 65 72 6B 69 74 6F 21 62 69 6F }

    condition : 
        filesize > 3MB
        and filesize < 7MB
        and all of them
}

rule Linux_trojan_Hello_Kitty {
    meta :
		creation_date = "18/03/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "9B8E532C87523053E76D5496FF1EED21A963F6C7CD95FE4D33BD8F68F84D839C"
        sample = "https://bazaar.abuse.ch/sample/556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed/"
        os = "Linux"

    strings :

        // CRYPTOGAMS
        $b1 = { 43 52 59 50 54 4F 47 41 4D 53}

        // <appro@openssl.org>
        $b2 = { 3C 61 70 70 72 6F 40 6F 70 65 6E 73 73 6C 2E 6F 72 67 3E }

        // kill -9
        $b3 = { 6B 69 6C 6C 20 2D 39 }

    condition :
        filesize > 60KB
        and filesize < 100KB
        and all of them
}