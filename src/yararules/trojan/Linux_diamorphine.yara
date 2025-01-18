rule Linux_diamorphine_5d637915 {
    meta : 
		creation_date = "18/01/2025"
        fingerprint = "650100F700FF98ADACE8B459176DE3E7FED1248128C6D52C3D6926417F60A666"
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