//
//  AUAuthorization.m
//  certificateUtility
//
//  Created by Danil Korotenko on 8/12/24.
//

#import "AUAuthorization.h"

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

    AuthorizationItem authenv[] =
    {
        { kAuthorizationEnvironmentUsername, strlen(aLogin), (void *)aLogin, 0 },
        { kAuthorizationEnvironmentPassword, strlen(aPassword), (void *)aPassword, 0 },
        { kAuthorizationEnvironmentShared, 0, NULL, 0 }
    };

    AuthorizationEnvironment env = { 3, authenv };

    AuthorizationRights *myAuthorizedRights = NULL;
    myStatus = AuthorizationCopyRights(myAuthorizationRef, &myRights,
        &env, myFlags, &myAuthorizedRights);


    aBlock();


    if (myAuthorizedRights)
    {
        AuthorizationFreeItemSet (myAuthorizedRights);
    }

    AuthorizationFree (myAuthorizationRef, kAuthorizationFlagDestroyRights);

    return myStatus;
}
