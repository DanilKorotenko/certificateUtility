//
//  main.m
//  certificateUtility
//
//  Created by Danil Korotenko on 8/5/24.
//

#import <Foundation/Foundation.h>
#import "../SecurityUtilities/SUCeritifcate.h"
#import "../SecurityUtilities/SUKeychain.h"

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        SUCeritifcate *certificate = [[SUCeritifcate alloc] initWithPath:@"testCertificate.der"];

        if (!certificate)
        {
            NSLog(@"No certificate");
            return 0;
        }

        OSStatus err = noErr;
        SUKeychain *keychain = [[SUKeychain alloc] initSystemKeychain];
        if (!keychain)
        {
            NSLog(@"No keychain");
            return 0;
        }

        if (![keychain containsCertificate:certificate])
        {
            err = [keychain addCertificate:certificate];
            if (err != noErr)
            {
                NSLog(@"SecCertificateAddToKeychain failure. Error: %d", err);
            }
        }
        else
        {
            NSLog(@"Certificate already in keychain");
        }

        err = SecTrustSettingsSetTrustSettings(certificate.certificateRef, kSecTrustSettingsDomainAdmin, NULL);

        if (err != noErr)
        {
            NSLog(@"SecTrustSettingsSetTrustSettings failure. Error: %d", err);
        }
    }
    return 0;
}
