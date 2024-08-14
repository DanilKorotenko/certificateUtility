//
//  SUKeychain.m
//  certificateUtility
//
//  Created by Danil Korotenko on 8/12/24.
//

#import "SUKeychain.h"

@interface SUKeychain ()

@property (readwrite) SecKeychainRef keychain;

@end

@implementation SUKeychain

- (instancetype)initSystemKeychain
{
    self = [super init];
    if (self)
    {
        SecKeychainRef keychain = NULL;
        SecKeychainCopyDomainDefault(kSecPreferencesDomainSystem, &keychain);

        if (!keychain)
        {
            return nil;
        }

        self.keychain = keychain;
    }
    return self;
}

- (void)dealloc
{
    if (self.keychain)
    {
        CFRelease(self.keychain);
    }
}

#pragma mark -

- (BOOL)containsCertificate:(SUCeritifcate *)aCertificate
{
    SecKeychainSearchRef searchRef = NULL;
    OSStatus status = SecKeychainSearchCreateFromAttributes(self.keychain, kSecCertificateItemClass, NULL, &searchRef);
    if (status || !searchRef)
    {
        return NO;
    }

    BOOL result = NO;

    SecKeychainItemRef candidate = NULL;
    while (SecKeychainSearchCopyNext(searchRef, &candidate) == noErr)
    {
        if (CFEqual(aCertificate.certificateRef, (SecCertificateRef)candidate))
        {
            result = YES;
            break;
        }
    }

    CFRelease(searchRef);

    return result;
}

- (OSStatus)addCertificate:(SUCeritifcate *)aCertificate
{
    return SecCertificateAddToKeychain(aCertificate.certificateRef, self.keychain);
}

@end
