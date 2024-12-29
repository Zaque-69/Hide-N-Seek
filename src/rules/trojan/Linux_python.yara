rule Linux_python_trojan { 
    meta : 
		creation_date = "27/10/2024"
        fingerprint = "efbf398143487477bdf999108b968e409018d8f79ed88a3965e2eacaf0a29e72"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // Failed to get _MEIPASS as PyObjec
        $b1 = { 46 61 69 6C 65 64 20 74 6F 20 67 65 74 20 5F 4D 45 49 50 41 53 53 20 61 73 20 50 79 4F 62 6A 65 63 }

        // WARNING: file already exists but should not:
        $b2 = { 57 41 52 4E 49 4E 47 3A 20 66 69 6C 65 20 61 6C 72 65 61 64 79 20 65 78 69 73 74 73 20 62 75 74 20 73 68 6F 75 6C 64 20 6E 6F 74 }
    
        // Could not read from file
        $b3 = { 43 6F 75 6C 64 20 6E 6F 74 20 72 65 61 64 20 66 72 6F 6D 20 66 69 6C 65 }

    condition : 
        all of them
}