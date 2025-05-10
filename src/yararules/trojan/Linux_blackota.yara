rule Linux_blackrota_trojan_5c9b30d5 {
    meta : 
		creation_date = "29/04/2025"
        update_date = "10.05.2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "4B32C0A411452E50C64E71061C9A50DA102C72220022C62279909DC4F5B4E74B"
        sample = "https://bazaar.abuse.ch/sample/5c9b30d502e2f103f089607ce699520f88154e3d7988a9db801f2a2a4378bf41"
        os = "Linux"

    strings : 

        // PrivateKey3617de4a
        $b1 = { 50 72 69 76 61 74 65 4B 65 79 33 36 31 37 64 65 34 61 39 36 32 36 }

        // BEGIN RSA
        $b2 = { 42 45 47 49 4E 20 52 53 41 }

        // TESTING KEY
        $b3 = { 54 45 53 54 49 4E 47 20 4B 45 59 }

    condition : 
        filesize > 4MB
        and all of them
}