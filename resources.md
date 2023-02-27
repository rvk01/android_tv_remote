# Miscellaneous

## icons for index

https://fontawesome.com/v5/docs/web/style/size
https://icons8.com/icons

### On request of

```
user: Mario
```

### Extra installation steps (to be moved to main page)

````
sudo apt-get install python3-protobuf
sudo apt-get install protobuf-compiler
protoc ./remotemessage.proto --python_out=./
protoc ./pairingmessage.proto --python_out=./
````

## Acknowledgments
This project wouldn't have been possible without these awesome projects which reverse-engineered these protocols.
 - [Aymkdn](https://github.com/Aymkdn)'s wiki on the protocol [Remote Control (v2)](https://github.com/Aymkdn/assistant-freebox-cloud/wiki/Google-TV-(aka-Android-TV)-Remote-Control-(v2))
 - [louis49](https://github.com/louis49/androidtv-remote)'s [androidtv-remote](https://github.com/louis49/androidtv-remote) js implementation (especially for the v2 proto files)

## Other simular projects

 - A GO implementation of [drosoCode](https://github.com/drosoCode/atvremote)
 - Another python implementation of [fsievers22](https://github.com/fsievers22/py_atvremote_

