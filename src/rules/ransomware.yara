rule Your_File_May_Use_Cryptography{

	strings:
	        $c1 = "cryptography" ascii wide
	        $c2 = "bytesToBeEncrypted" ascii wide        

	condition : any of them
} 

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

	condition : ($header at 0 or $pyFile at 0) and any of ($c*)
}
rule wannaCry_Positive{
	meta : 
		author = "Z4que - All rights reserved"
		date = "22/01/2024"

	strings:
		$header = {4D 5A}

		$c1 = "cmd.exe" ascii wide
		$c2 = "che.exe" ascii wide
		$c3 = "kdl.exe" ascii wide
		$c4 = "taskdl.exe" ascii wide
		$c5 = "taskse.exe" ascii wide
		$c6 = "mssecsvc.exe" ascii wide

		$c7 = "mnses7nxf743znk7.onion" ascii wide
		$c8 = "r5x6sdigdz4q7f6q.onion" ascii wide
		$c9 = "sw7xmbms2ivmt5og.onion" ascii wide

		$c10 = "WANACRY!" ascii wide
		$c11 = "C:\\%s\\wodglslsh"

	condition : $header at 0 and 4 of ($c*)
}
rule lokiLocker_Positive{
	meta : 
		author = "Z4que - All rights reserved"
		date = "27/01/2024"

	strings:
		$header = { 4D 5A }

        	//"your files have been encrypted"
		$c3 = { 59 00 6F 00 75 00 72 00 20 00 66 00 69 00 6C 00 65
		        00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65
		        00 6E 00 20 00 65 00 6E 00 63 00 72 00 79 00 70 00 74 00 65
		        00 64}
		
		//"Your compuer is locked. Please do not close this window"
		$c4 = { 59 00 6F 00 75 00 72 00 20 00 63 00 6F 00 6D 00 70
		        00 75 00 74 00 65 00 72 00 20 00 69 00 73 00 20 00 6C 00 6F
		        00 63 00 6B 00 65 00 64 00 2E 00 20 00 50 00 6C 00 65 00 61
		        00 73 00 65 00 20 00 64 00 6F 00 20 00 6E 00 6F 00 74 00 20
		        00 63 00 6C 00 6F 00 73 00 65 00 20 00 74 00 68 00 69 00 73
		        00 20 00 77 00 69 00 6E 00 64 00 6F 00 77 00 20 00 61 00 73
		        00 20 00 74 00 68 00 61 00 74 00 20 00 77 00 69 00 6C 00 6C
		        00 20 00 72 00 65 00 73 00 75 00 6C 00 74 00 20 00 69 00 6E
		        00 20 00 73 00 65 00 72 00 69 00 6F 00 75 00 73 00 20 00 63
		        00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 20 00 64 00 61
		        00 6D 00 61 00 67 00 65 }

        //"locked"
        $c5 = { 6C 00 6F 00 63 00 6B 00 65 00 64 }

        $c6 = "C:\\Users\\Tyler\\Desktop\\hidden-tear-master\\hidden-tear\\hidden-tear\\obj\\Debug\\VapeHacksLoader.pdb" ascii wide

	condition : ($header at 0) and any of ($c*)
}
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

	condition : ($header at 0) and any of ($c*)
}
rule petya_Positive{
	meta : 
		author = "Z4que - All rights reserved"
		date = "28/01/2024"

	strings:
		$header = { 4D 5A }

		//Illegal byte sequence
		$c1 = { 49 6C 6C 65 67 61 6C 20 62 79 74 65 20 73 65 71 75 65 6E 63 65 } 

		$c2 = "d:/re/workspace/8-2-build-windows-i586-cygwin/jdk8u73/6086/install/src/windows/au/jucheck/UpdateManager.cpp" ascii wide
		$c3 = "d:\re\\workspace\\8-2-build-windows-i586-cygwin\\jdk8u73\\6086\\install\\src\\common\\share\\Version.h" ascii wide

	condition : ($header at 0) and any of ($c*)
}
rule notpetya_Positive{
	meta : 
		author = "Z4que - All rights reserved"
		date = "28/01/2024"

	strings:
		$header = { 4D 5A }

		//"Send your Bitcoin Wallet and personal installation"
		$c1 = { 53 00 65 00 6E 00 64 00 20 00 79 00 6F 00 75 00 72 00 20
			00 42 00 69 00 74 00 63 00 6F 00 69 00 6E 00 20 00 77 00 61 00 6C
			00 6C 00 65 00 74 00 20 00 49 00 44 00 20 00 61 00 6E 00 64 00 20
			00 70 00 65 00 72 00 73 00 6F 00 6E 00 61 00 6C 00 20 00 69 00 6E
			00 73 00 74 00 61 00 6C 00 6C 00 61 00 74 00 69 00 6F 00 6E 00 } 

		//*The wallet ID you need to send the BTC
		$c2 = { 31 00 4D 00 7A 00 37 00 31 00 35 00 33 00 48 00 4D 00 75 00
			78 00 58 00 54 00 75 00 52 00 32 00 52 00 31 00 74 00 37 00 38 00 
			6D 00 47 00 53 00 64 00 7A 00 61 00 41 00 74 00 4E 00 62 00 42 00 
			57 00 58 } 

		//"300 Worth of Bitcoin"
		$c3 = { 24 00 33 00 30 00 30 00 20 00 77 00 6F 00 72 00 74 00 68 00 20
			00 6F 00 66 00 20 00 42 00 69 00 74 00 63 00 6F 00 69 00 6E }

		//"encrypt"
		$c4 = { 65 00 6E 00 63 00 72 00 79 00 70 00 74 } 

		$c5 = "WARNING: DO NOT TURN OFF YOUR PC! IF YOU ABORT THIS PROCESS, YOU COULD DESTROY ALL OF YOUR DATA!" fullword ascii
		$c6 = "Ooops, your important files are encrypted" fullword ascii

	condition : ($header at 0) and any of ($c*) and filesize < 500KB
}
rule PowerPoint_positive {
    meta : 
       author = "Z4que - All rights reverved"
	  date = "7/03/2024"

    strings : 
        $header = { 4D 5A }

        	$c1 = "sys3.exe" ascii wide
        	$c2 = "fucked-up-shit" ascii wide

        	$c3 = { 73 71 6C 68 6F 73 74 2E 64 6C 6C 00 53 65 53 68 75
         	        74 64 6F 77 6E 50 72 69 76 69 6C 65 67 65 }
        
        	$c4 = { 68 74 74 70 3A 2F 2F 00 52 4C }

    condition : 
     
        ( $header at 0 ) and all of ( $c* ) 
}

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

	condition : ($header at 0 ) and any of ($c*) and 2 of ($b*) and $u
}
