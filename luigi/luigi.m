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
 * luigi.m
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

#import "luigi.h"

#import <objc/runtime.h>
#import <JRSwizzle.h>
#include <libproc.h>

char *g_list[] =
{
    "/System/Library/CoreServices/CoreLocationAgent.app/Contents/MacOS/CoreLocationAgent",
    "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
    "/System/Library/CoreServices/ManagedClient.app/Contents/MacOS/ManagedClient",
    "/System/Library/CoreServices/Setup Assistant.app/Contents/MacOS/Setup Assistant",
    "/System/Library/PreferencePanes/Accounts.prefPane/Contents/XPCServices/com.apple.preferences.users.remoteservice.xpc/Contents/MacOS/com.apple.preferences.users.remoteservice",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/MacOS/DateAndTime",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/Resources/DateTime.prefPane/Contents/MacOS/DateTime",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/Resources/TimeZone.prefPane/Contents/MacOS/TimeZone",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/Resources/TimeZone.prefPane/Contents/Resources/AppleModemSettingTool",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/Resources/TimeZone.prefPane/Contents/Resources/TimeZoneAdminTool",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/Resources/TimeZone.prefPane/Contents/Resources/zset",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/XPCServices/com.apple.preference.datetime.remoteservice.xpc/Contents/MacOS/com.apple.preference.datetime.remoteservice",
    "/System/Library/PreferencePanes/DesktopScreenEffectsPref.prefPane/Contents/Resources/ScreenEffects.prefPane/Contents/MacOS/ScreenEffects",
    "/System/Library/PreferencePanes/iCloudPref.prefPane/Contents/XPCServices/com.apple.preferences.icloud.remoteservice.xpc/Contents/MacOS/com.apple.preferences.icloud.remoteservice",
    "/System/Library/PreferencePanes/InternetAccounts.prefPane/Contents/XPCServices/com.apple.preferences.internetaccounts.remoteservice.xpc/Contents/MacOS/com.apple.preferences.internetaccounts.remoteservice",
    "/System/Library/PreferencePanes/Network.prefPane/Contents/XPCServices/com.apple.preference.network.remoteservice.xpc/Contents/MacOS/com.apple.preference.network.remoteservice",
    "/System/Library/PreferencePanes/ParentalControls.prefPane/Contents/XPCServices/com.apple.preferences.parentalcontrols.remoteservice.xpc/Contents/MacOS/com.apple.preferences.parentalcontrols.remoteservice",
    "/System/Library/PreferencePanes/PrintAndScan.prefPane/Contents/XPCServices/com.apple.preference.printfax.remoteservice.xpc/Contents/MacOS/com.apple.preference.printfax.remoteservice",
    "/System/Library/PreferencePanes/Security.prefPane/Contents/XPCServices/com.apple.preference.security.remoteservice.xpc/Contents/MacOS/com.apple.preference.security.remoteservice",
    "/System/Library/PreferencePanes/SharingPref.prefPane/Contents/XPCServices/com.apple.preferences.sharing.remoteservice.xpc/Contents/MacOS/com.apple.preferences.sharing.remoteservice",
    "/System/Library/PreferencePanes/Speech.prefPane/Contents/XPCServices/com.apple.preference.speech.remoteservice.xpc/Contents/MacOS/com.apple.preference.speech.remoteservice",
    "/System/Library/PreferencePanes/StartupDisk.prefPane/Contents/MacOS/StartupDisk",
    "/System/Library/PreferencePanes/StartupDisk.prefPane/Contents/XPCServices/com.apple.preference.startupdisk.remoteservice.xpc/Contents/MacOS/com.apple.preference.startupdisk.remoteservice",
    "/System/Library/PreferencePanes/TimeMachine.prefPane/Contents/XPCServices/com.apple.prefs.backup.remoteservice.xpc/Contents/MacOS/com.apple.prefs.backup.remoteservice",
    "/System/Library/PreferencePanes/UniversalAccessPref.prefPane/Contents/XPCServices/com.apple.preference.universalaccess.remoteservice.xpc/Contents/MacOS/com.apple.preference.universalaccess.remoteservice",
    "/System/Library/PrivateFrameworks/AOSKit.framework/Versions/A/XPCServices/com.apple.iCloudHelper.xpc/Contents/MacOS/com.apple.iCloudHelper",
    "/System/Library/PrivateFrameworks/SpeechObjects.framework/Versions/A/SpeechDataInstallerd.app/Contents/MacOS/SpeechDataInstallerd",
    "/System/Library/PrivateFrameworks/SystemAdministration.framework/Versions/A/Resources/UpdateSettingsTool",
    "/System/Library/PrivateFrameworks/SystemAdministration.framework/XPCServices/writeconfig.xpc/Contents/MacOS/writeconfig",
    "/System/Library/SystemProfiler/SPFirewallReporter.spreporter/Contents/MacOS/SPFirewallReporter",
    "/System/Library/UserEventPlugins/AutoTimeZone.plugin/Contents/MacOS/AutoTimeZone",
    "/usr/bin/tmutil",
    "/usr/libexec/locationd",
    "/usr/sbin/networksetup",
    "/usr/sbin/systemsetup",
    "/Applications/System Preferences.app/Contents/MacOS/System Preferences",
    NULL
};

NSMutableDictionary *gMatchList;

void __attribute__ ((constructor))
init(void)
{
    /* init dictionary with all the binaries that connect to the XPC service*/
    gMatchList = [NSMutableDictionary new];
    for (char **n = g_list; *n != NULL; n++)
    {
        [gMatchList setValue:@"" forKey:[NSString stringWithCString:*n encoding:NSUTF8StringEncoding]];
    }
    
    /* Swizzle the original method with our own version */
    /* this is messy, needs some love <3 */
    Class hackClass = (Class)objc_lookUpClass("WriteConfigDispatch");
    if (hackClass != nil)
    {
        Class myClass = [Luigi class];
        SEL mySelector = @selector(hookedListener:shouldAcceptNewConnection:);
        Method myMethod = class_getInstanceMethod(myClass, mySelector);
        IMP myIMP = class_getMethodImplementation(myClass, mySelector);
        
        class_addMethod(hackClass,
                        mySelector,
                        myIMP,
                        method_getTypeEncoding(myMethod));
        NSError *error = nil;
        [hackClass jr_swizzleMethod:@selector(listener:shouldAcceptNewConnection:) withMethod:mySelector error:&error];
        if (error)
        {
            NSLog(@"%@", error);
        }
    }
    
}

@implementation Luigi

/*
 * this is our swizzled listener version where we will allow or not the request to proceed
 * we first verify if the requesting process is on the allowed list
 * and then we verify its code signature to verify if it wasn't tampered with
 */
- (BOOL)hookedListener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection
{
    char errorMsg[PROC_PIDPATHINFO_MAXSIZE + 1024] = {0};
    
    int logFile = open("/tmp/rootpipe_fix_log", O_RDWR | O_CREAT | O_APPEND, 0644);
    if (logFile < 0)
    {
        /* some error message ? */
        return NO;
    }
    
    /* retrieve information about the process trying to connect to the XPC service */
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {0};
    /* the connecting PID is available to us from the second parameter */
    pid_t targetPid = [newConnection processIdentifier];
    /* and retrieve the binary executable path related to this PID */
    int ret = proc_pidpath(targetPid, pathbuf, sizeof(pathbuf));
    /* reject anything in case of error */
    if (ret <= 0)
    {
        snprintf(errorMsg, sizeof(errorMsg), "Failed to retrieve proc_pidpath for PID %d.\n", targetPid);
        write(logFile, errorMsg, sizeof(errorMsg));
        close(logFile);
        return NO;
    }
    
    /* now we need to verify if it's in the allowed list */
    /* Always use full path else a copy could be run from somewhere else */
    if ([gMatchList objectForKey:[NSString stringWithCString:pathbuf encoding:NSUTF8StringEncoding]] == nil)
    {
        snprintf(errorMsg, sizeof(errorMsg), "Binary %s with PID %d tried unauthorized connection.\n", pathbuf, targetPid);
        write(logFile, errorMsg, sizeof(errorMsg));
        close(logFile);
        return NO;
    }
    /* verify if the binary was tampered with aka code signature is valid */
    SecStaticCodeRef ref = NULL;
    SecRequirementRef req = NULL;
    
    NSURL *url = [NSURL fileURLWithPath:[NSString stringWithFormat:@"%s", pathbuf] isDirectory:NO];
    OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &ref);
    if (ref == NULL || status != noErr)
    {
        snprintf(errorMsg, sizeof(errorMsg), "Failed to obtain certificate info for %s with PID %d. Error: %d.\n", pathbuf, targetPid, status);
        write(logFile, errorMsg, sizeof(errorMsg));
        close(logFile);
        return NO;
    }
    NSString *reqStr = [NSString stringWithFormat:@"anchor apple"];
    status = SecRequirementCreateWithString((__bridge CFStringRef)reqStr, kSecCSDefaultFlags, &req);
    if (status != noErr || req == NULL)
    {
        if (req != NULL)
        {
            CFRelease(req);
        }
        CFRelease(ref);
        snprintf(errorMsg, sizeof(errorMsg), "Failed to create requirement string for %s with PID %d.\n", pathbuf, targetPid);
        write(logFile, errorMsg, sizeof(errorMsg));
        close(logFile);
        return NO;
    }
    status = SecStaticCodeCheckValidity(ref, kSecCSCheckAllArchitectures, req);
    /* if the code signature is valid we let it proceed by calling the original method */
    if (status == noErr)
    {
        snprintf(errorMsg, sizeof(errorMsg), "Connection authorized to binary %s with PID %d.\n", pathbuf, targetPid);
        write(logFile, errorMsg, sizeof(errorMsg));
        close(logFile);
        CFRelease(ref);
        CFRelease(req);
        /* call the original method so we can proceed with connection to the XPC */
        return [self hookedListener:listener shouldAcceptNewConnection:newConnection];
    }
    else
    {
        snprintf(errorMsg, sizeof(errorMsg), "Code signature verification failed for %s with PID %d.\n", pathbuf, targetPid);
        write(logFile, errorMsg, sizeof(errorMsg));
        close(logFile);
        CFRelease(req);
        CFRelease(ref);
        return NO;
    }
}

@end
