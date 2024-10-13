rule DeriaLock_Ransomware_Positive{
	meta : 
		author = "Z4que - All rights reserved"
		date = "09/02/2024"

	strings:
		$header = { 4D 5A }
		
		$c1 = "LOGON.exe" ascii wide
		$c2 = "mscoree.dll" ascii wide

		//This background image
		$b1 = { 74 00 68 00 69 00 73 00 2E 00 42 00 61 00 63 00 6B 00
			67 00 72 00 6F 00 75 00 6E 00 64 00 49 00 6D 00 61 00
			67 00 65 }

		//CreateKey.strPassword.CreateIVEncryprORDescyprFile.strInputFile.strOutputFile
		$b2 = { 43 72 65 61 74 65 4B 65 79 00 73 74 72 50 61 73 73 77
			6F 72 64 00 43 72 65 61 74 65 49 56 00 45 6E 63 72 79
			70 74 4F 72 44 65 63 72 79 70 74 46 69 6C 65 00 73 74
			72 49 6E 70 75 74 46 69 6C 65 00 73 74 72 4F 75 74 70
			75 74 46 69 6C 65 }

		//Decryption !
		$b3 = { 44 00 45 00 43 00 52 00 59 00 50 00 54 00 49 00 4F 00 4E 00 21 }
		
		//think that is a bad decision ice try mate =)
		$b4 = { 74 00 68 00 69 00 6E 00 6B 00 20 00 74 00 68 00 61 00 74 00 20
			00 69 00 73 00 20 00 61 00 20 00 62 00 61 00 64 00 20 00 64 00
			65 00 63 00 69 00 73 00 69 00 6F 00 6E 00 00 1F 69 00 63 00 65
			00 20 00 74 00 72 00 79 00 20 00 6D 00 61 00 74 00 65 00 20 00
			3D 00 29 }

		$u = "http://wallup.net" ascii wide

	condition : 
		($header at 0 ) 
		and any of ($c*) 
		and 2 of ($b*) 
		and $u
}
