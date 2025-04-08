rule Linux_royal_ramsomware_06abc46d { 
    meta : 
		creation_date = "08/04/2024"
        github = "https://github.com/Zaque-69"
        fingerprint = "01628F64D1C3FC94E0F57CC743D70FE06FD9F248C42BA132D0D9CA81B89499EB"
        sample = "https://bazaar.abuse.ch/download/06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725/"
        os = "Linux"

    strings : 

        // If you are reading this
        $b1 = { 49 66 20 79 6F 75 20 61 72 65 20 72 65 61 64 69 6E 67 20 74 68 69 73 }

        // were hit by Royal ransomware
        $b2 = { 77 65 72 65 20 68 69 74 20 62 79 20 52 6F 79 61 6C 20 72 61 6E 73 6F 6D 77 61 72 65 }

        // royal2xthig
        $b3 = { 72 6F 79 61 6C 32 78 74 68 69 67 }

        // .onion
        $b4 = { 2E 6F 6E 69 6F 6E }

    condition : 
        filesize > 2MB
        and filesize < 3MB
        and all of them
}