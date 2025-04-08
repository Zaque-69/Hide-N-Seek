rule Linux_python_trojan_ed077ecc { 
    meta : 
		creation_date = "27/10/2024"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "E39A91EC5567ED13DADC217F4EFE02B32208710FEA5B467B95B75D6FABD5EEDC"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/ed077ecceeb2c851f45a095df2cc33c54b4ac17f03a28d1d9696a819de827e20"
        os = "Linux"

    strings : 
        
        // Failed to get _MEIPASS as PyObjec
        $b1 = { 46 61 69 6C 65 64 20 74 6F 20 67 65 74 20 5F 4D 45 49 50 41 53 53 20 61 73 20 50 79 4F 62 6A 65 63 }

        // WARNING: file already exists but should not:
        $b2 = { 57 41 52 4E 49 4E 47 3A 20 66 69 6C 65 20 61 6C 72 65 61 64 79 20 65 78 69 73 74 73 20 62 75 74 20 73 68 6F 75 6C 64 20 6E 6F 74 }
    
        // Could not read from file
        $b3 = { 43 6F 75 6C 64 20 6E 6F 74 20 72 65 61 64 20 66 72 6F 6D 20 66 69 6C 65 }

    condition : 
        filesize > 2MB
        and all of them
}

rule Linux_python_trojan_03bb1cfd { 
    meta : 
		creation_date = "27/10/2024"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "39AE51F9270F668C3C3759F20DA3BE7C33FA305D0E542C2BE36E304DCCBC5908"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/03bb1cfd9e45844701aabc549f530d56f162150494b629ca19d83c1c696710d7"
        os = "Linux"

    strings : 
        
        // Cannot dlsym for Py_
        $b1 = { 43 61 6E 6E 6F 74 20 64 6C 73 79 6D 20 66 6F 72 20 50 79 5F }

    condition : 
        filesize > 1MB
        and all of them
}

rule Linux_python_trojan_3993bc5c { 
    meta : 
		creation_date = "28/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "B9177EBAFA5AD9830DEC3D4ED613ED32993A651818F895DF5BAB5C9EFBF444BD"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/3993bc5c3cdfe470fab6f6b932a7e741630f0212a7f18249a61123e3b324edef"
        os = "Linux"

    strings : 

        // PyObject
        $b1 = { 50 79 4F 62 6A 65 63 74 }
    
        // Somebody screwed up
        $b2 = { 53 6F 6D 65 62 6F 64 79 20 73 63 72 65 77 65 64 20 75 70 }

    condition : 
        all of them
}