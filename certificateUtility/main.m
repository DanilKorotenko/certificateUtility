//
//  main.m
//  certificateUtility
//
//  Created by Danil Korotenko on 8/5/24.
//

#import <Foundation/Foundation.h>
#import "../SecurityUtilities/SUCeritifcate.h"
#import "../SecurityUtilities/SUKeychain.h"

AuthorizationEnvironment createEnvironment(void)
{
    char *login = "trustadmin";
    char *pass = "pass123456";

    static AuthorizationItem authenv[] =
    {
        { kAuthorizationEnvironmentUsername },
        { kAuthorizationEnvironmentPassword },
        { kAuthorizationEnvironmentShared }
    };

    AuthorizationEnvironment env = { 0, authenv };
    authenv[0].valueLength = strlen(login);
    authenv[0].value = login;
    authenv[1].valueLength = strlen(pass);
    authenv[1].value = pass;
    env.count = 3;

    return env;
}

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

        OSStatus err = noErr;

        AuthorizationRef myAuthorizationRef = NULL;
        OSStatus myStatus;
        myStatus = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
            kAuthorizationFlagDefaults, &myAuthorizationRef);

        AuthorizationItem myItems[1];

        myItems[0].name = "com.apple.trust-settings.admin";
        myItems[0].valueLength = 0;
        myItems[0].value = NULL;
        myItems[0].flags = 0;

        AuthorizationRights myRights;
        myRights.count = sizeof (myItems) / sizeof (myItems[0]);
        myRights.items = myItems;

        AuthorizationFlags myFlags = kAuthorizationFlagDefaults | kAuthorizationFlagExtendRights;

        AuthorizationEnvironment env = createEnvironment();

        AuthorizationRights *myAuthorizedRights = NULL;
        myStatus = AuthorizationCopyRights (myAuthorizationRef, &myRights,
            &env, myFlags, &myAuthorizedRights);

        if (myStatus != noErr)
        {
            NSLog(@"AuthorizationCopyRights failure. Error: %d", err);
        }

        SUKeychain *keychain = [[SUKeychain alloc] initSystemKeychain];

        if (!keychain)
        {
            NSLog(@"No keychain");
            return 0;
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

        if (myAuthorizedRights)
        {
            myStatus = AuthorizationFreeItemSet (myAuthorizedRights);
        }

        myStatus = AuthorizationFree (myAuthorizationRef,
            kAuthorizationFlagDestroyRights);
    }
    return 0;
}
