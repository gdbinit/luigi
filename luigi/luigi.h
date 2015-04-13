/*
 *
 *  ,--.     ,--. ,--.    ,-.-')   ,----.     ,-.-')
 *  |  |.-') |  | |  |    |  |OO) '  .-./-')  |  |OO)
 *  |  | OO )|  | | .-')  |  |  \ |  |_( O- ) |  |  \
 *  |  |`-' ||  |_|( OO ) |  |(_/ |  | .--, \ |  |(_/
 * (|  '---.'|  | | `-' /,|  |_.'(|  | '. (_/,|  |_.'
 *  |      |('  '-'(_.-'(_|  |    |  '--'  |(_|  |
 *  `------'  `-----'     `--'     `------'   `--'
 *
 * Luigi - The dynamic library to fix rootpipe
 *
 * This is a dynamic library that is injected into writeconfig vulnerable binary
 * Its task is to control access to this binary
 * Apple's fix for Yosemite does this using entitlements
 * In this case we only allow access to specific binaries and verify their code signature
 * Dynamic library injection via DYLD_INSERT_LIBRARIES is not possible
 * because all these binaries were injected with a __RESTRICT segment
 *
 * Have I already told you how much I hate Objective-C? No? Yes I hate it!
 * So this code might be crappier than strictly necessary!
 *
 * Copyright (c) fG!, 2015. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * luigi.h
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#import <Foundation/Foundation.h>
#import <Security/SecCode.h>

@interface Luigi : NSObject

- (BOOL)hookedListener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection;

@end
