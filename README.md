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