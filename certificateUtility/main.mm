//
//  main.m
//  certificateUtility
//
//  Created by Danil Korotenko on 8/5/24.
//

#import <Foundation/Foundation.h>
#import "../IdentityUtilities/IUIdentity.h"
#import "../IdentityUtilities/IUIdentityQuery.h"

const char *userLogin = "trustadmin";
const char *userPass = "pass123456";

const char *tool = "addCertificateAndMakeTrusted";

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

        AuthorizationRef myAuthorizationRef = NULL;
        OSStatus myStatus = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
            kAuthorizationFlagDefaults, &myAuthorizationRef);

        AuthorizationItem myItems[2];

        myItems[0].name = "com.apple.trust-settings.admin";
        myItems[0].valueLength = 0;
        myItems[0].value = NULL;
        myItems[0].flags = 0;

        myItems[1].name = kAuthorizationRightExecute;
        myItems[1].valueLength = strlen(tool);
        myItems[1].value = (void *)tool;
        myItems[1].flags = 0;

        AuthorizationRights myRights;
        myRights.count = sizeof (myItems) / sizeof (myItems[0]);
        myRights.items = myItems;

        AuthorizationFlags myFlags = kAuthorizationFlagDefaults | kAuthorizationFlagExtendRights;

        AuthorizationEnvironment env = createEnvironment(userLogin, userPass);

        AuthorizationRights *myAuthorizedRights = NULL;
        myStatus = AuthorizationCopyRights(myAuthorizationRef, &myRights,
            &env, myFlags, &myAuthorizedRights);

        FILE *outputFile;
        char *args[1];
        args[0] = NULL;
        AuthorizationExecuteWithPrivileges(myAuthorizationRef, tool, kAuthorizationFlagDefaults, args, &outputFile);


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
