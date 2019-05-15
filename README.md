# A sane AES128 cypto for nodejs

Standard crypto module uses the same openssl library but relays on
upper layer where the streaming implementation withholds the last 
processed block and uses callbacks which might force you to do await 
and other tricks or just make it unusable for decrypting streaming data 
such as TCP communication. 

This module is based on elementary AES operation from openssl and implements 
CBC by itself this avoiding and delays in data processing 

All you need is openssl development files installed libssl-dev package in ubuntu
and a node-gyp with it's dependacines such as the gcc compiler and friends.

Just do
`sudo apt install libssl-dev;  npm install https://github.com/sdrsdr/sane_aes128_cbc.git`
and you should be all set

see eample/sane_cypto.js for example


# License

This module is LGPLv3 licensed you're free to use and modify it but you have to contribute back 
the changes you've made :)
