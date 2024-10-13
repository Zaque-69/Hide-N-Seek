rule pythonCryptography_Positive{
	meta : 
		author = "Z4que - All rights reserved"
		date = "22/01/2024"

	strings:
		$header = {7F 45 4C 46}
		$pyFile = "import" ascii wide
		$c1 = "xcryptography" ascii wide
		$c2 = "cryptography.hazmat.primitives" ascii wide
		$c3 = "cryptography.fernet" ascii wide
		$c4 = "import cryptography" ascii wide

	condition : 
		($header at 0 or $pyFile at 0) 
		and any of ($c*)
}