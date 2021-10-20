# Private browser memory forensics

## Browsers to look at 
- Chrome
- Firefox
- Internet Explorer
- Edge
- Vivaldi

## Instructions for memory capture
- Download the windows vm [here](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)
- Run vm with 4GB ram
- Transfer your browser installer to the vm **DO NOT DOWNLOAD IT ON THE BROWSER**
- See below for the things you are to browse
- Do not close the browsers
- Run Belkasoft Ramcapturer

## What to capture
Chrome:
- www.google.com
- search for "brave browser"
- go to brave site, download brave installer
- www.youtube.com
- search for rick roll
- watch it 

Edge:
- www.google.com
- search for "firefox"
- go to firefox site, download firefox installer
- www.youtube.com
- search for rick roll
- watch it

The rest:
- duckduckgo.com
- search for malware
- go to wikipedia page for malware https://en.wikipedia.org/wiki/Malware
- search for picoctf 
- go to picoctf site https://picoctf.org/
- click on log in https://play.picoctf.org/login
- login with credentials:
  - owadeeoh
  - soonIwillord123
  - click on "Obedient Cat" challenge and download the file

# Volatility setup
```
git clone https://github.com/volatilityfoundation/volatility3.git
python3 -m pip install -r requirements.txt
python3 setup.py build 
python3 setup.py install
```

# Running volatility
```
cd <project directory here>
vol -f <mem file> --plugin-dir . chrome_history
```

# Wei Jie's notes
For chromium based browsers, I'm searching for the leaf headers using yara

So far I have come up with the rule for the URL table of the History file

```plaintext
id -> 00 (always NULL, takes the row_id as the id)
url -> variable length, can be as long as 2 bytes  (part of [2-4])
title -> variable length, can be as long as 2 bytes (part of [2-4]) 
visit_count -> (09 | 08 | 01) (1 byte integer, can be 0 or 1)
typed_count -> (09 | 08 | 01) (1 byte integer, can be 0 or 1)
last_visit_time -> 4 byte integer (06)
hidden -> (09 | 08 | 01) (1 byte integer, can be 0 or 1)
```

So far I've only seen hidden being 0 or 1 and nothing else but from superponible's history needle it included `\x01\x01http` which searches for hex 01 in hidden and last_visit_time which doesn't seem to make sense.

```yara
rule URL_HEADER { 
  strings: 
    $a = { 00 [2-4] ( 09 | 08 | 01 ) ( 09 | 08 | 01 ) 06 ( 08 | 01 ) } 
  condition: 
    $a 
}
```


# References
- Chrome & firefox history by superponible (https://github.com/superponible/volatility-plugins)
- Chrome Ragamuffin by cube0x8 (https://github.com/cube0x8/chrome_ragamuffin)
- SqliteFind by mbrown1413 (https://github.com/mbrown1413/SqliteFind)
- Reading sqlite files at the hex level (https://askclees.com/2020/11/20/sqlite-databases-at-hex-level/)