//
//  main.m
//  certificateTool
//
//  Created by Danil Korotenko on 8/22/24.
//

#import <Foundation/Foundation.h>

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        NSLog(@"Hello world");

        SecCodeRef me = NULL;

        SecCodeCopySelf(kSecCSDefaultFlags, &me);

        SecStaticCodeRef meStatic = NULL;

        SecCodeCopyStaticCode(me, kSecCSDefaultFlags, &meStatic);

        CFDictionaryRef infoCF = NULL;

        SecCodeCopySigningInformation(meStatic, kSecCSDefaultFlags, &infoCF);

        NSDictionary *info = CFBridgingRelease(infoCF);

        NSDictionary *entitlements = [info objectForKey:(NSString *)kSecCodeInfoEntitlementsDict];

        NSLog(@"entitlements: %@", entitlements);

    }
    return 0;
}
