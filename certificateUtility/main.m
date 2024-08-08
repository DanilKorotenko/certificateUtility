//
//  main.m
//  certificateUtility
//
//  Created by Danil Korotenko on 8/5/24.
//

#import <Foundation/Foundation.h>

SecCertificateRef certificateWithPath(NSString *aPath)
{
    NSURL *url = [NSURL fileURLWithPath:aPath isDirectory:NO];
    NSData *rootCertData = [NSData dataWithContentsOfURL:url];

    CFDataRef rootCerDataRef = (__bridge CFDataRef)(rootCertData);

    SecCertificateRef result = SecCertificateCreateWithData(NULL, rootCerDataRef);

    if (!result)
    {
        NSLog(@"Unable to create certificate from path: %@", aPath);
    }
    return result;
}

NSString *certificateGetName(SecCertificateRef aCertificate)
{
    NSString *result = nil;
    CFStringRef nameRef = NULL;
    if ((SecCertificateCopyCommonName(aCertificate, &nameRef) == noErr) && nameRef != NULL)
    {
        result = CFBridgingRelease(nameRef);
    }
    return result;
}

SecCertificateRef findCertificate(SecKeychainRef aKeychain, NSString *aName)
{
    OSStatus status = noErr;
    SecKeychainSearchRef searchRef = NULL;

    SecKeychainItemRef candidate = NULL;

    status = SecKeychainSearchCreateFromAttributes(aKeychain, kSecCertificateItemClass, NULL, &searchRef);
    if (status || !searchRef)
    {
        return (SecCertificateRef)candidate;
    }

    while (SecKeychainSearchCopyNext(searchRef, &candidate) == noErr)
    {
        SecCertificateRef cert = (SecCertificateRef)candidate;

        NSString *certName = certificateGetName(cert);
        if (!certName)
        {
            if (candidate)
            {
                CFRelease(candidate);
            }
            continue; // no name, so no match is possible
        }

        if ([certName isEqualToString:aName])
        {
            break;
        }
    }

    CFRelease(searchRef);

    return (SecCertificateRef)candidate;
}

BOOL certificateInKeychain(SecKeychainRef aKeychain, SecCertificateRef aCertificate)
{
    NSString *certName = certificateGetName(aCertificate);
    SecCertificateRef cert = findCertificate(aKeychain, certName);
    return CFEqual(cert, aCertificate);
}

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
        SecCertificateRef certificate = certificateWithPath(path);

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

        SecKeychainRef keychain = NULL;
        SecKeychainCopyDomainDefault(kSecPreferencesDomainSystem, &keychain);

        if (!keychain)
        {
            NSLog(@"No keychain");
            return 0;
        }

        if (!certificateInKeychain(keychain, certificate))
        {
            err = SecCertificateAddToKeychain(certificate, keychain);
            if (err != noErr)
            {
                NSLog(@"SecCertificateAddToKeychain failure. Error: %d", err);
            }
        }
        else
        {
            NSLog(@"Certificate already in keychain");
        }

        err = SecTrustSettingsSetTrustSettings(certificate, kSecTrustSettingsDomainAdmin, NULL);
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
