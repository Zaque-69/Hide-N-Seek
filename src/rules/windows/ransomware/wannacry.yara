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

	condition : 
		$header at 0 
		and 4 of ($c*)
}