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

	condition : 
		($header at 0) 
		and any of ($c*)
}