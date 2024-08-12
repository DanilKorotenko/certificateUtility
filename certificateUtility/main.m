//
//  main.m
//  certificateUtility
//
//  Created by Danil Korotenko on 8/5/24.
//

#import <Foundation/Foundation.h>
#import "../SecurityUtilities/SUCeritifcate.h"
#import "../SecurityUtilities/SUKeychain.h"
#import "../AuthorizationUtilities/AUAuthorization.h"

const char *userLogin = "trustadmin";
const char *userPass = "pass123456";

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        if (argc < 2)
        {
            NSLog(@"usage: %s <certificate-path>", argv[0]);
            return 0;
        }

        NSString *path = [NSString stringWithUTF8String:argv[1]];
        SUCeritifcate *certificate = [[SUCeritifcate alloc] initWithPath:path];

        if (!certificate)
        {
            return 0;
        }

        OSStatus myStatus = executeTrustSettingsAdminAuthorizedBlock(userLogin, userPass,
            ^{
                OSStatus err = noErr;
                SUKeychain *keychain = [[SUKeychain alloc] initSystemKeychain];
                if (!keychain)
                {
                    NSLog(@"No keychain");
                    return;
                }

                if (![keychain containsCertificate:certificate])
                {
                    err = [keychain addCertificate:certificate.certificateRef];
                    if (err != noErr)
                    {
                        NSLog(@"SecCertificateAddToKeychain failure. Error: %d", err);
                    }
                }
                else
                {
                    NSLog(@"Certificate already in keychain");
                }

                err = [certificate setTrustSettings];
                if (err != noErr)
                {
                    NSLog(@"SecTrustSettingsSetTrustSettings failure. Error: %d", err);
                }
            });

        if (myStatus != noErr)
        {
            NSLog(@"Authorization failure. Error: %d", myStatus);
        }

    }
    return 0;
}
