rule Linux_generic_e157d5c7 {
    meta : 
		creation_date = "06/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "825A9A46870FF13626B8703AD7ACFC64B2C61E4792B6838419EEE3D543E38184"
        sample = "https://bazaar.abuse.ch/download/e157d5c74cf949af2105f513b93bc5f1e745c33d2e8e28aca333c52ec4d0ec11/"
        os = "Linux"

    strings : 

        // =========Backtrace: =========
        $b1 = { 42 61 63 6B 74 72 61 63 65 3A 20 3D 3D 3D 3D 3D 3D 3D 3D 3D }

        // corrupted double-linked
        $b2 = { 63 6F 72 72 75 70 74 65 64 20 64 6F 75 62 6C 65 2D 6C 69 6E 6B 65 64 }

        // ANSI_X3.4-1968//TRANSLIT
        $b3 = { 41 4E 53 49 5F 58 33 2E 34 2D 31 39 36 38 2F 2F 54 52 41 4E 53 4C 49 54 }

    condition : 
        filesize > 400KB
        and filesize < 600KB
        and all of them
}