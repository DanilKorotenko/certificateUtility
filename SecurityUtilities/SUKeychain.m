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

- (SUCeritifcate *)findCertificateWithName:(NSString *)aName
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
        SUCeritifcate *cert = [[SUCeritifcate alloc] initWithCertificate:(SecCertificateRef)candidate];

        if ([aName isEqualToString:cert.name])
        {
            result = cert;
            break;
        }
    }

    CFRelease(searchRef);

    return result;
}

- (BOOL)containsCertificate:(SUCeritifcate *)aCertificate
{
    NSString *certName = aCertificate.name;
    SUCeritifcate *cert = [self findCertificateWithName:certName];
    return [aCertificate isEqual:cert];
}

- (OSStatus)addCertificate:(SecCertificateRef)aCertificate
{
    return SecCertificateAddToKeychain(aCertificate, self.keychain);
}

@end
