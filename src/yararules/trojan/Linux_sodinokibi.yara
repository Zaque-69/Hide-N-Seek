rule Linux_sodinokibi_trojan_f864922f { 
    meta : 
		creation_date = "10/04/2024"
        github = "https://github.com/Zaque-69"
        fingerprint = "6C90F5FB1B187BAD84FA188D8408758ADC2614D91ED6CEEB9CCDF31BA0EDD74A"
        sample = "https://bazaar.abuse.ch/download/f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5/"
        os = "Linux"

    strings : 

        // !!!BY DEFAULT THIS SOFTWARE
        $b1 = { 21 21 21 42 59 20 44 45 46 41 55 4C 54 20 54 48 49 53 20 53 4F 46 54 57 41 52 45 }

        // USES 50 THREADS!!!
        $b2 = { 55 53 45 53 20 35 30 20 54 48 52 45 41 44 53 21 21 21 }

        // let's encrypt anyway..
        $b3 = { 6C 65 74 27 73 20 65 6E 63 72 79 70 74 20 61 6E 79 77 61 79 2E 2E }

    condition : 
        filesize > 75KB
        and filesize < 150KB
        and all of them
}