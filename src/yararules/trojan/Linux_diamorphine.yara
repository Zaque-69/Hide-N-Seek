rule Linux_diamorphine_trojan_5d637915 {
    meta : 
		creation_date = "18/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "C1F1386EF2B1F3A5A22420DE663FE86AB835CF05FFC6501899516D0502A586D5"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/5d637915abc98b21f94b0648c552899af67321ab06fb34e33339ae38401734cf"
        os = "Linux"

    strings : 

        // diamorphine
        $b1 = { 64 69 61 6D 6F 72 70 68 69 6E 65 }

        // author=m0nad
        $b2 = { 61 75 74 68 6F 72 3D 6D 30 6E 61 64 }

    condition : 
        all of them
}