rule Linux_hacktool_e0367097 {
    meta : 
		creation_date = "28/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "E67CA25AC0BB620E4D96E4CF5FFCC48E8C2F298FB44E516961068538C04267D3"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/e0367097a1450c70177bbc97f315cbb2dcb41eb1dc052f522c9e8869e084bd0f"
        os = "Linux"

    strings : 

        // try something like "--range
        $b1 = { 74 72 79 20 73 6F 6D 65 74 68 69 6E 67 20 6C 69 6B 65 20 22 2D 2D 72 61 6E 67 65 }

    condition : 
        all of them
}