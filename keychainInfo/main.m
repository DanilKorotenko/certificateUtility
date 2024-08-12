//
//  main.m
//  keychainInfo
//
//  Created by Danil Korotenko on 8/12/24.
//

#import <Foundation/Foundation.h>
#import "../SecurityUtilities/SUCeritifcate.h"
#import "../SecurityUtilities/SUKeychain.h"

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        NSLog(@"Hello, keychain info!");
        SUCeritifcate *certificate = [[SUCeritifcate alloc] initWithPath:@"testCertificate.der"];

//        OSStatus err = noErr;
//        SUKeychain *keychain = [[SUKeychain alloc] initSystemKeychain];
//        if (!keychain)
//        {
//            NSLog(@"No keychain");
//            return 0;
//        }
//
//        if (![keychain containsCertificate:certificate])
//        {
//            err = [keychain addCertificate:certificate.certificateRef];
//            if (err != noErr)
//            {
//                NSLog(@"SecCertificateAddToKeychain failure. Error: %d", err);
//            }
//        }
//        else
//        {
//            NSLog(@"Certificate already in keychain");
//        }

//        NSLog(@"isTrusted: %@", certificate.isTrusted ? @"YES" : @"NO");

        NSLog(@"sha1: %@", certificate.sha1);
    }
    return 0;
}
