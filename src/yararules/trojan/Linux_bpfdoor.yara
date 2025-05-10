rule Linux_bpfdoor_trojan {
    meta : 
		creation_date = "10/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "9BDFDF3619807BA30CD90DF5BDE8056964D7B2F8FC3193F4E965FD7363B3E46B"
        samples = "https://bazaar.abuse.ch/browse/tag/bpfdoor/"
        os = "Linux"

    strings : 

        // ptem.ldterm.ttcompat
        $b1 = { 70 74 65 6D 00 6C 64 74 65 72 6D 00 74 74 63 6F 6D 70 61 74 }

        // RC4-MD5.-----BEGIN
        $b2 = { 52 43 34 2D 4D 44 35 00 2D 2D 2D 2D 2D 42 45 47 49 4E }

        // PRIVATE KEY-----
        $b3 = { 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D }

        // MIICXAIBAAKBgQCyzeYCrtef
        $b4 = { 4D 49 49 43 58 41 49 42 41 41 4B 42 67 51 43 79 7A 65 59 43 72 74 65 66 }

        // g8TWQOqxLJlO5Xzl+JIsTg==
        $b5 = { 67 38 54 57 51 4F 71 78 4C 4A 6C 4F 35 58 7A 6C 2B 4A 49 73 54 67 3D 3D }

        // emct7i+Q9mQFA0JJ1Gf9yd+5
        $b6 = { 65 6D 63 74 37 69 2B 51 39 6D 51 46 41 30 4A 4A 31 47 66 39 79 64 2B 35 }

        // END RSA
        $b7 = { 45 4E 44 20 52 53 41 }

        // CERTIFICATE
        $b8 = { 43 45 52 54 49 46 49 43 41 54 45 }

        // bH2SfTqfAc93z5aa048
        $b9 = { 62 48 32 53 66 54 71 66 41 63 39 33 7A 35 61 61 30 34 38 }

        // KVq2U1j19MNP
        $b10 = { 4B 56 71 32 55 31 6A 31 39 4D 4E 50 }

        // FDN9ywBvBdXKH9OfXpnLe4vkPZkBQNCSdRn
        $b11 = { 46 44 4E 39 79 77 42 76 42 64 58 4B 48 39 4F 66 58 70 6E 4C 65 34 76 6B 50 5A 6B 42 51 4E 43 53 64 52 6E }

        // does not match the public certificate
        $b12 = { 64 6F 65 73 20 6E 6F 74 20 6D 61 74 63 68 20 74 68 65 20 70 75 62 6C 69 63 20 63 65 72 74 69 66 69 63 61 74 65 }

    condition : 
        ( filesize < 100KB )
        or ( filesize < 3MB )
        and 6 of them
}
