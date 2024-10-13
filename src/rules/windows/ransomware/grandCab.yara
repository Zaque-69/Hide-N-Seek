rule grandCab_Positive{
	meta : 
		author = "Z4que - All rights reserved"
		date = "27/01/2024"

	strings:
		$header = { 4D 5A }

	        $c1 = { 4A 61 6E 75 61 72 79 00 44 65 63 00 4E 6F 76 00 4F
		        63 74 00 53 65 70 00 41 75 67 00 4A 75 6C 00 4A 75 6E 00 4D
		        61 79 00 41 70 72 00 4D 61 72 00 46 65 62 00 4A 61 6E 00 }
		
		        //installation program operation not complete
		        $c2 = { 4F 00 70 00 65 00 72 00 61 00 7A 00 69 00 6F 00 6E
		        00 65 00 20 00 64 00 65 00 6C 00 20 00 70 00 72 00 6F 00 67
		        00 72 00 61 00 6D 00 6D 00 61 00 20 00 64 00 69 00 20 00 69
		        00 6E 00 73 00 74 00 61 00 6C 00 6C 00 61 00 7A 00 69 00 6F
		        00 6E 00 65 00 20 00 6E 00 6F 00 6E 00 20 00 63 00 6F 00 6D
		        00 70 00 6C 00 65 00 74 00 61 00 74 00 61 }

	condition : 
		($header at 0) 
		and any of ($c*)
}