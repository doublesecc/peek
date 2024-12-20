# peek
## Overview
peek is a python tool to search files for strings that are defined in a wordlist or an argument.

```
python3 ./peek.py -h
usage: peek.py [-h] (-f FILE | -d DIR) (-w WORDLIST | -s STRING) [-e {md5,sha1,sha256,b64,url}] [-v] [-vv] [-o OUTPUT] [-p] [--case-sensitive] [-t THRESHOLD] [--no-banner]

Search a file or directory for words from a wordlist or a string.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to the file to search in
  -d DIR, --dir DIR     Path to the directory to search in recursively
  -w WORDLIST, --wordlist WORDLIST
                        Path to the wordlist file
  -s STRING, --string STRING
                        String to search for
  -e {md5,sha1,sha256,b64,url}, --encode {md5,sha1,sha256,b64,url}
                        Specify encoding type (md5, sha1, sha256, b64, url)
  -v, --verbose         Verbose mode, print each check result
  -vv, --very-verbose   Very verbose mode, print all details
  -o OUTPUT, --output OUTPUT
                        Save matched results to the specified output file
  -p, --partial         Enable partial word matching
  --case-sensitive      Enable case-sensitive search (default is case-insensitive)
  -t THRESHOLD, --threshold THRESHOLD
                        Partial match threshold 0.0-1 (default is 0.75)
  --no-banner           Disable banner print
```

## Examples
### Searching a single file for 50% partial string matches using a wordlist
```
python3 ./peek.py -f <file> -w <wordlist> -p -t 0.5
```

### Searching the current directory recursively for full string matches using a string that is b64 encoded
```
python3 ./peek.py -d . -s 'password' -e 64
```
