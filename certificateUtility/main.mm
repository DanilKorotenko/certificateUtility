//
//  main.m
//  certificateUtility
//
//  Created by Danil Korotenko on 8/5/24.
//

#import <Foundation/Foundation.h>
#import "../SecurityUtilities/SUCeritifcate.h"
#import "../SecurityUtilities/SUKeychain.h"
#import "../IdentityUtilities/IUIdentity.h"
#import "../IdentityUtilities/IUIdentityQuery.h"

const char *userLogin = "trustadmin";
const char *userPass = "pass123456";

AuthorizationEnvironment createEnvironment(const char *aLogin, const char *aPassword)
{
    static AuthorizationItem authenv[] =
    {
        { kAuthorizationEnvironmentUsername },
        { kAuthorizationEnvironmentPassword },
        { kAuthorizationEnvironmentShared }
    };

    AuthorizationEnvironment env = { 0, authenv };
    authenv[0].valueLength = strlen(aLogin);
    authenv[0].value = (void *)aLogin;
    authenv[1].valueLength = strlen(aPassword);
    authenv[1].value = (void *)aPassword;
    env.count = 3;

    return env;
}

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        NSString *userName = [NSString stringWithUTF8String:userLogin];
        IUIdentity *user = [IUIdentityQuery localUserWithFullName:userName];
        if (!user)
        {
            NSString *userPassword = [NSString stringWithUTF8String:userPass];

            user = [IUIdentity newHiddenUserWithFullName:userName password:userPassword];

            NSError *error = nil;
            if (![user commit:&error])
            {
                NSLog(@"%@", error);
                return 0;
            }

            IUIdentity *administrators = [IUIdentityQuery administratorsGroup];
            if (!administrators)
            {
                NSLog(@"%@", @"No administrators group");
                return 0;
            }

            [administrators addMember:user];

            if (![administrators commit:&error])
            {
                NSLog(@"%@", error);
                return 0;
            }
        }

        SUCeritifcate *certificate = [[SUCeritifcate alloc] initWithPath:@"testCertificate.der"];

        if (!certificate)
        {
            return 0;
        }

        __block OSStatus err = noErr;
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

        AuthorizationRef myAuthorizationRef = NULL;
        OSStatus myStatus = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
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

        AuthorizationEnvironment env = createEnvironment(userLogin, userPass);

        AuthorizationRights *myAuthorizedRights = NULL;
        myStatus = AuthorizationCopyRights(myAuthorizationRef, &myRights,
            &env, myFlags, &myAuthorizedRights);

        err = SecTrustSettingsSetTrustSettings(certificate.certificateRef, kSecTrustSettingsDomainAdmin, NULL);

        if (err != noErr)
        {
            NSLog(@"SecTrustSettingsSetTrustSettings failure. Error: %d", err);
        }

        if (myAuthorizedRights)
        {
            AuthorizationFreeItemSet (myAuthorizedRights);
        }

        AuthorizationFree (myAuthorizationRef, kAuthorizationFlagDestroyRights);

        if (myStatus != noErr)
        {
            NSLog(@"Authorization failure. Error: %d", myStatus);
        }
    }
    return 0;
}
