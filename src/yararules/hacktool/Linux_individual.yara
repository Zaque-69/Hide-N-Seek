rule Linux_hacktool_e0367097 {
    meta : 
		creation_date = "28/01/2025"
        fingerprint = "F647965EA3FE6CD431DA62412CB873DE61F93B2E405CAEFB470C4942ECD04852"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // try something like "--range
        $b1 = { 74 72 79 20 73 6F 6D 65 74 68 69 6E 67 20 6C 69 6B 65 20 22 2D 2D 72 61 6E 67 65 }

    condition : 
        all of them
}