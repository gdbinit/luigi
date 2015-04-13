Luigi - The userland component to fix rootpipe

Copyright (c) fG!, 2015. All rights reserved.  
reverser@put.as - https://reverse.put.as

This is the dynamic library injected into the vulnerable writeconfig process.  
Its purpose is to control access to this XPC service. Contains a list of hardcoded binaries that are allowed to connect and also verifies if their code signature has been tampered with.

Not a finest example of Objective-C swizzling! Done in a hurry but it works :-)

Tested with Mavericks 10.9.5.  

Don't forget to send a message to Apple thanking for keeping you vulnerable ;-
)  

Have fun,  
fG!
