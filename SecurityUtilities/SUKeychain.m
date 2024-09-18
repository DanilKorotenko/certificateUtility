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

+ (SUKeychain *)systemKeychain
{
    return [[SUKeychain alloc] initWithDomain:kSecPreferencesDomainSystem];
}

+ (SUKeychain *)loginKeychain
{
    return [[SUKeychain alloc] initWithDomain:kSecPreferencesDomainUser];
}

+ (SUKeychain *)commonKeychain
{
    return [[SUKeychain alloc] initWithDomain:kSecPreferencesDomainCommon];
}

+ (OSStatus)deleteCertificate:(SUCeritifcate *)aCertificate
{
    return SecKeychainItemDelete((SecKeychainItemRef)aCertificate.certificateRef);
}

- (instancetype)initWithDomain:(SecPreferencesDomain)aDomain
{
    self = [super init];
    if (self)
    {
        SecKeychainRef keychain = NULL;
        SecKeychainCopyDomainDefault(aDomain, &keychain);

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

- (SUCeritifcate *)findCertificateBySHA1:(NSString *)aSHA1
{
    SecKeychainSearchRef searchRef = NULL;
    OSStatus status = SecKeychainSearchCreateFromAttributes(self.keychain, kSecCertificateItemClass, NULL, &searchRef);
    if (status || !searchRef)
    {
        return nil;
    }

    SUCeritifcate *result = nil;

    SecKeychainItemRef candidate = NULL;
    while (SecKeychainSearchCopyNext(searchRef, &candidate) == noErr)
    {
        SUCeritifcate *certificate = [[SUCeritifcate alloc] initWithCertificate:(SecCertificateRef)candidate];
        if ([certificate.sha1 caseInsensitiveCompare:aSHA1] == NSOrderedSame)
        {
            result = certificate;
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
