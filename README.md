# Android TV Remote

## About this project
This is a python3 script for Android TV and Google TV remote control.

It uses the newer protocol of [remote services](https://www.apkmirror.com/apk/google-inc/android-tv-remote-service-android-tv/) version >= 5<br>

## Quickstart
Check on your Android TV device the `Remote Services` version (in Settings > Apps > See all apps > Android TV Remote Service).<br>
The version should be >= 5.

This script runs on a Reaspberry Pi to control an Android TV.<br>
It can accept keycodes via a http connection and will pass these on to the Android TV or Box.

To install, follow these steps:

Goto home directory, clone this git and make the script executable

    cd ~  
    git clone https://github.com/rvk01/android_tv_remote.git``
    cd android_tv_remote
    chmod +x android_tv_remote.py

Run the script one first time to create client.pem (certificate) and server.txt (chosen device)  

    ./andoid_tv_remote.py

Choose your device and check if everything works correctly.  

Install, enable and start the script as service

    sudo cp atvr.service /etc/systemd/system/atvr.service
    sudo systemctl enable atvr.service
    sudo systemctl start atvr.service

You can now browse to http://ip_of_your_device:6468/index (or /index0 for all keys) for a small http remote to test page.

View messages from the script (-f is follow output live)

    journalctl -u -f atvr

## Usage

## Acknowledgments
This project wouldn't have been possible without these awesome projects which reverse-engineered these protocols.
 - [Aymkdn](https://github.com/Aymkdn)'s wiki on the protocol [V2](https://github.com/Aymkdn/assistant-freebox-cloud/wiki/Google-TV-(aka-Android-TV)-Remote-Control-(v2))
 - [louis49](https://github.com/louis49/androidtv-remote)'s [androidtv-remote](https://github.com/louis49/androidtv-remote) js implementation (especially for the v2 proto files)
