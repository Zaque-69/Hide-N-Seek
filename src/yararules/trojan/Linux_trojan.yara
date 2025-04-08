rule Linux_trojan_2d8e89b1 {
    meta : 
		creation_date = "11/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "3B49392E8C7CB3177188D0EEFA7E9020CCB1BCD04F260BAEF8714332BFAABE9E"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/2d8e89b1febe64a6c35ec2fbbe1535bca4a0f4744f560e9737a17050e66cd6a6"
        os = "Linux"

    strings : 

        // Shellcode Length: %d
        $b1 = { 53 68 65 6C 6C 63 6F 64 65 20 4C 65 6E 67 74 68 3A 20 25 64 }

    condition : 
        all of them
}

rule Linux_trojan_2da44d9d {
    meta : 
		creation_date = "11/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "C3E9D84F085AB65E50BCDAA01ACDBB6156C103C98F48CD22F81EBE33824444D5"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/2da44d9d925078449fba3d1f8efd81fa9833e5e83d7da8d69a62427790c05741"
        os = "Linux"

    strings : 

        // Error in dlsym: %s
        $b1 = { 45 72 72 6F 72 20 69 6E 20 64 6C 73 79 6D 3A 20 25 73 }

    condition : 
        all of them
}