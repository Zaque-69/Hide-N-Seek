import
    re

# REGex to find a specific combination that matches a calendar date (example : 20160609)
proc allDatesFromFile * (filename: string): seq[string] =
    var 
        list: seq[string] = @[]
        dateregex = re" (\d{4})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])"
    
    for line in lines(filename):
        list.add(findAll(line, dateregex))

    list