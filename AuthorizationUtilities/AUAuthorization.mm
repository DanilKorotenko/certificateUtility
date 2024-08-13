//
//  AUAuthorization.m
//  certificateUtility
//
//  Created by Danil Korotenko on 8/12/24.
//

#import "AUAuthorization.h"

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

OSStatus executeTrustSettingsAdminAuthorizedBlock(const char *aLogin, const char *aPassword, void (^aBlock)(void))
{
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

    AuthorizationEnvironment env = createEnvironment(aLogin, aPassword);

    AuthorizationRights *myAuthorizedRights = NULL;
    myStatus = AuthorizationCopyRights (myAuthorizationRef, &myRights,
            &env, myFlags, &myAuthorizedRights);


    aBlock();


    if (myAuthorizedRights)
    {
        AuthorizationFreeItemSet (myAuthorizedRights);
    }

    AuthorizationFree (myAuthorizationRef, kAuthorizationFlagDestroyRights);

    return myStatus;
}
