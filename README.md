# Android TV Remote

## About this project
This tool implements the remote control protocol for Android TV and Google TV.

The v1 is for the old [Android TV Remote Control](https://www.apkmirror.com/apk/google-inc/remote-control/) app <br>
The v2 is for the newer [Google TV](https://play.google.com/store/apps/details?id=com.google.android.videos) app used when your android tv's [remote services](https://www.apkmirror.com/apk/google-inc/android-tv-remote-service-android-tv/) version is >= 5 <br>
The [anymote protocol](https://code.google.com/archive/p/anymote-protocol/) (old protocol for google tv < 2014) is not supported.

## Quickstart
Check on your android tv device the `Remote Services` version (in Settings > Apps > See all apps > Android TV Remote Service).
If the version is >= 5, you sould use the v2 protocol.

First, start the pairing process `./atvremote -ip="192.168.1.20" -version=2 -pair`<br>
Then, you can send a list of keypress like this (this sould open the settings) `./atvremote -ip="192.168.1.20" -version=2 command="HOME;HOME;UP;RIGHT;RIGHT;ENTER`


This is a python script running on a Reaspberry Pi to control an Android TV.
It can accept keycodes via http connection and will pass these on to the Android TV or Box.

To install, follow these steps:

Goto home directory, clone this git and make the script executable

    cd ~  
    git clone https://github.com/rvk01/android_tv_remote.git``
    cd android_tv_remote
    chmod +x android_tv_remote.py

Run the script one first time to create client.pem (certificate) and server.txt (chosen device)  

    ./andoid_tv_remote.py

Choose your device and check if everything works correctly.  
You can browse to http://ip_of_your_device:6468/index for a small http remote to test.

Install, enable and start the script as service

    sudo cp atvr.service /etc/systemd/system/atvr.service
    sudo systemctl enable atvr.service
    sudo systemctl start atvr.service

View messages from the script (-f is follow output live)

    journalctl -u -f atvr

## Usage

## Acknowledgments
This project wouldn't have been possible without these awesome projects which reverse-engineered these protocols.
 - [Aymkdn](https://github.com/Aymkdn)'s wiki on the protocols [V1](https://github.com/Aymkdn/assistant-freebox-cloud/wiki/Google-TV-(aka-Android-TV)-Remote-Control) and [V2](https://github.com/Aymkdn/assistant-freebox-cloud/wiki/Google-TV-(aka-Android-TV)-Remote-Control-(v2))
 - [louis49](https://github.com/louis49/androidtv-remote)'s [androidtv-remote](https://github.com/louis49/androidtv-remote) js implementation (especially for the v2 proto files)

 - [](https://raw.githubusercontent.com/drosoCode/atvremote/)
