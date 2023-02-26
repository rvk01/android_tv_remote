# Android TV Remote

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

