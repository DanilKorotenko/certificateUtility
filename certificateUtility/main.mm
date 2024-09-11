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
#import "../IdentityUtilities/IUIdentity.h"
#import "../IdentityUtilities/IUIdentityQuery/IUIdentityQuery.h"

const char *userLogin = "trustadmin";
const char *userPass = "pass123456";

bool checkUser()
{
    NSError *error = nil;
    NSString *userName = [NSString stringWithUTF8String:userLogin];
    IUIdentity *user = [IUIdentity localUserWithFullName:userName];
    if (!user)
    {
        NSString *userPassword = [NSString stringWithUTF8String:userPass];

        user = [IUIdentity newHiddenUserWithFullName:userName password:userPassword];

        if (![user commit:&error])
        {
            NSLog(@"user commit error: %@", error);
            return false;
        }
    }

    if (!user.isAdmin)
    {
        IUIdentity *administrators = [IUIdentity administratorsGroup];
        if (!administrators)
        {
            NSLog(@"No administrators group");
            return false;
        }

        [administrators addMember:user];

        if (![administrators commit:&error])
        {
            NSLog(@"administrators commit error: %@", error);
            return false;
        }
    }

    return true;
}

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        if (!checkUser())
        {
            return 0;
        }

        SUCeritifcate *certificate = [[SUCeritifcate alloc] initWithPath:@"testCertificate.der"];

        if (!certificate)
        {
            return 0;
        }

        SUKeychain *keychain = [[SUKeychain alloc] initSystemKeychain];
        if (!keychain)
        {
            NSLog(@"No keychain");
            return 0;
        }

        if (![keychain containsCertificate:certificate])
        {
            OSStatus err = [keychain addCertificate:certificate];
            if (err != noErr)
            {
                NSLog(@"SecCertificateAddToKeychain failure. Error: %d", err);
            }
        }
        else
        {
            NSLog(@"Certificate already in keychain");
        }

        OSStatus myStatus = executeTrustSettingsAdminAuthorizedBlock(userLogin, userPass,
            ^{
                OSStatus err = SecTrustSettingsSetTrustSettings(certificate.certificateRef, kSecTrustSettingsDomainAdmin, NULL);
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
