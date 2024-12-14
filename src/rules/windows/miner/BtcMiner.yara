rule BtcMiner_Virus_Positive{
	meta : 
		author = "Z4que - All rights reverved"
		date = "14/12/2024"

	strings:
		$header = { 4D 5A }

		// NsCpuCNMiner32.exe
		$a1 = { 4E 73 43 70 75 43 4E 4D 69 6E 65 72 33 32 2E 65 78 65 }

		// HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a2 = { 48 4B 43 55 5C 53 4F 46 54 57 41 52 45 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 52 75 6E }
		
		// /c reg add
		$a3= { 2F 63 20 72 65 67 20 61 64 64 }

		// C:/Documents and settings
		$a4 = { 43 00 3A 00 5C 00 44 00 6F 00 63 00 75 00 6D 00 65 00 6E 00 74 00 73 00 20 00 61 00 6E 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6E 00 67 00 73 00 5C }
			
		//"C:/Users"
		$a5 = { 43 00 3A 00 5C 00 55 00 73 00 65 00 72 00 73 00 5C }

	condition : 
		( $header at 0 ) 
		and all of ( $a* ) 
}
