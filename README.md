# TRIGGER WARNING

EXTREMELY ugly code!!!
do not read if you are sensitive!!

# Update

+ added my own obfuscator (delltaxa/obfusex) (setup-script and holder-script will now be obfusscated)
+ old tmp folders are now getting deleted (if you restart it)

# Usage

Example:

```
bash superspread 1.51/46.17.211.21@exploit_.py
```

Arguments explainted:

1.51 is the end of the private ip ` 192.168.1.51 ` after you put in ur end, you use a slash and put in your public ip
or the one of the for example ngrok website domain at the end you write an @ and then the path to the malware you want
to deploy (PYTHON only) (no executables)

# what it does

1. it will make a temporary directory to store the files for the webserver
2. it will create 4 files in there with a random name
3. FIlES:
   1. the malware
   2. a setup script for the malware
   3. some other python os.system script to install and run the setup script
   4. a powershell payload
4. It will make a shorter powershell script to get and execute the long obfuscated script (not hard to deobf)
5. It will start a php webserver and host the tmp direcory

# WARNING

It is not that hard (except for maybe beginners) to deobfuscate so you should obfuscate it if you don't want anyone to read your code

# images

![image](https://user-images.githubusercontent.com/114283067/209446717-1aa0be9d-e376-437f-aff1-69972547dd91.png)

