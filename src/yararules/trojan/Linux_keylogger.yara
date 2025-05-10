rule Linux_trojan_6e4829d8 {
    meta : 
		creation_date = "09/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = ""
        sample = "https://bazaar.abuse.ch/download/6e4829d8847e9d48628b7a2e55fb29b1de9d5c5377621bfaa5e28b006ff1f6bc"
        os = "Linux"

    strings : 

        // PyUnicode_Type
        $b1 = { 50 79 55 6E 69 63 6F 64 65 5F 54 79 70 65 }

        // Module 'keylogger'
        $b2 = { 4D 6F 64 75 6C 65 20 27 6B 65 79 6C 6F 67 67 65 72 27 }
		
		// has already been imported
        $b3 = { 68 61 73 20 61 6C 72 65 61 64 79 20 62 65 65 6E 20 69 6D 70 6F 72 74 65 64 }

		// METH_KEYWORDS
        $b4 = { 4D 45 54 48 5F 4B 45 59 57 4F 52 44 53 }

		// Key.space
		$b5 = { 4B 65 79 2E 73 70 61 63 65 }
		
		// requests
		$b6 = { 72 65 71 75 65 73 74 73 }

		// Listener
		$b7 = { 4C 69 73 74 65 6E 65 72 }

    condition : 
		filesize > 50KB
		and filesize < 120KB
        and 4 of ( $b* )
}