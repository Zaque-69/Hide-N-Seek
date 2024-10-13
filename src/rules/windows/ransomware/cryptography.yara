rule Your_File_May_Use_Cryptography{

	strings:
	        $c1 = "cryptography" ascii wide
	        $c2 = "bytesToBeEncrypted" ascii wide        

	condition : 
		any of them
} 