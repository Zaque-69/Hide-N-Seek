rule Linux_Python_ransomware {
	meta : 
		creation_date = "28/12/2024"
		fingerprint = "6cd299023fc459e94890033f92c97279fbc592dd2bafdea2b65d183ac063bd41"
		github = "https://github.com/Zaque-69"
		os = "Linux"

	strings:
		// import
		$import = { 69 6D 70 6F 72 74 }
		
		// cryptography.hazmat.primitives
		$c1 = { 63 72 79 70 74 6F 67 72 61 70 68 79 2E 68 61 7A 6D 61 74 2E 70 72 69 6D 69 74 69 76 65 73 }
		
		// cryptography.fernet
		$c2 = { 63 72 79 70 74 6F 67 72 61 70 68 79 2E 66 65 72 6E 65 74 }

		// import cryptography
		$c3 = { 69 6D 70 6F 72 74 20 63 72 79 70 74 6F 67 72 61 70 68 79 }

	condition : 
		( $import at 0) 
		and any of ($c* )
}
