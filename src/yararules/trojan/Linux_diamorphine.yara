rule Linux_diamorphine__trojan_5d637915 {
    meta : 
		creation_date = "18/01/2025"
        fingerprint = "E344F438ABF23AD88A8024A0D192C83B0B95CB233B2D074F689E71037EF1CAB4"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // diamorphine
        $b1 = { 64 69 61 6D 6F 72 70 68 69 6E 65 }

        // author=m0nad
        $b2 = { 61 75 74 68 6F 72 3D 6D 30 6E 61 64 }

    condition : 
        all of them
}