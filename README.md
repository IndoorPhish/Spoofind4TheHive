# Spoofind4TheHive
Pull a list of newly registered domains and check them against a list of regex searches and create an alert in TheHive.

Add regex searches to a file named Search.txt in the same directory as the PowerShell script.
The format of the file should be:

- Line 1: ---Google spoofs---
- Line 2: .*g[0o]gle.*
- Line 3: ---Another Search---
- Line 4: .*bing\.com

Change the API URI on line 11 of the PS1 file to where you are hosting your instance of TheHive. Then create a file named in the same directory named TheHiveAPI - this should contain only your API key.
