//
//  SUCeritifcate.m
//  certificateUtility
//
//  Created by Danil Korotenko on 8/12/24.
//

#import "SUCeritifcate.h"
#import "NSData+SHA1.h"
#import "NSData+HexString.h"

@interface SUCeritifcate ()

@property (readwrite) SecCertificateRef certificateRef;
@property (readonly) NSArray *adminTrustSettings;

@end

@implementation SUCeritifcate

@synthesize name;
@synthesize adminTrustSettings;
@synthesize sha1;

- (instancetype)initWithCertificate:(SecCertificateRef)aCertificate
{
    self = [super init];
    if (self)
    {
        if (aCertificate == NULL)
        {
            return nil;
        }
        self.certificateRef = (SecCertificateRef)CFRetain(aCertificate);
    }
    return self;
}

- (instancetype)initWithPath:(NSString *)aPath
{
    self = [super init];
    if (self)
    {
        NSURL *url = [NSURL fileURLWithPath:aPath isDirectory:NO];
        NSData *certData = [NSData dataWithContentsOfURL:url];

        CFDataRef certDataRef = (__bridge CFDataRef)(certData);

        SecCertificateRef result = SecCertificateCreateWithData(NULL, certDataRef);

        if (!result)
        {
            return nil;
        }

        self.certificateRef = result;
    }
    return self;
}

- (void)dealloc
{
    if (self.certificateRef)
    {
        CFRelease(self.certificateRef);
    }
}

- (BOOL)isEqual:(id)other
{
    if (other == self)
    {
        return YES;
    }
    else if (![super isEqual:other])
    {
        return NO;
    }
    else
    {
        SUCeritifcate *otherCertificate = (SUCeritifcate *)other;
        return CFEqual(self.certificateRef, otherCertificate.certificateRef);
    }
}

- (NSUInteger)hash
{
    return [super hash];
}

#pragma mark -

- (NSString *)name
{
    if (name == nil)
    {
        CFStringRef nameRef = NULL;
        if ((SecCertificateCopyCommonName(self.certificateRef, &nameRef) == noErr) && nameRef != NULL)
        {
            name = CFBridgingRelease(nameRef);
        }
    }
    return name;
}

- (NSArray *)adminTrustSettings
{
    if (adminTrustSettings == nil)
    {
        CFArrayRef trustSettings = NULL;
        if (SecTrustSettingsCopyTrustSettings(self.certificateRef, kSecTrustSettingsDomainAdmin, &trustSettings) == noErr && trustSettings)
        {
            adminTrustSettings = CFBridgingRelease(trustSettings);
        }
    }
    return adminTrustSettings;
}

- (BOOL)isTrusted
{
    return self.adminTrustSettings != nil;
}

- (NSString *)sha1
{
    if (sha1 == nil)
    {
        NSData *certData = CFBridgingRelease(SecCertificateCopyData(self.certificateRef));
        NSData *sha1Data = certData.sha1;
        sha1 = sha1Data.hexString;
    }
    return sha1;
}

#pragma mark -

- (OSStatus)installAdminTrustSettings
{
    return SecTrustSettingsSetTrustSettings(self.certificateRef, kSecTrustSettingsDomainAdmin, NULL);
}

@end
