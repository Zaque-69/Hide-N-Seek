rule Linux_stowaway_trojan_b50bdfa4 {
    meta : 
		creation_date = "01/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "4B3D095C76B8BDBDF189D3766CC63CF10C1C811EA47595862B62338E28AA1B66"
        source = "https://bazaar.abuse.ch/download/b50bdfa4dc778404fda39499f2627c4c510fb7c650daee5147e851090b3ab820/"
        os = "Linux"

    strings : 

        // Stowaway/pkg/share
        $b1 = { 53 74 6F 77 61 77 61 79 2F 70 6B 67 2F 73 68 61 72 65 }

        // ssh.AuthMethod
        $b2 = { 73 73 68 2E 41 75 74 68 4D 65 74 68 6F 64 }

        // &vendor/golang.org
        $b3 = { 26 76 65 6E 64 6F 72 2F 67 6F 6C 61 6E 67 2E 6F 72 67 }

        // nistp521
        $b4 = { 6E 69 73 74 70 35 32 31 }

    condition : 
        filesize > 4MB
        and filesize < 8MB
        and all of them
}