rule Linux_blackmatter_ransomware_6a7b7147 {
	meta : 
		creation_date = "29/04/2024"
		github = "https://github.com/Zaque-69"
		fingerprint = "F2D2013A20ABA4163AF32A9ABB72295F12C5E51DC0B6096028A009A82324BD32"
		sample = "https://bazaar.abuse.ch/download/6a7b7147fea63d77368c73cef205eb75d16ef209a246b05698358a28fd16e502/"
		os = "Linux"

	strings:
		
		// void app::files_proc::encrypt_single_file
        $b1 = { 76 6F 69 64 20 61 70 70 3A 3A 66 69 6C 65 73 5F 70 72 6F 63 3A 3A 65 6E 63 72 79 70 74 5F 73 69 6E 67 6C 65 5F 66 69 6C 65 }

        // N5boost
        $b2 = { 4E 35 62 6F 6F 73 74 }

	condition : 
		filesize > 1MB
        and filesize < 3MB
		and all of them
}