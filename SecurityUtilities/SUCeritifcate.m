//
//  SUCeritifcate.m
//  certificateUtility
//
//  Created by Danil Korotenko on 8/12/24.
//

#import "SUCeritifcate.h"

@interface SUCeritifcate ()

@property (readwrite) SecCertificateRef certificate;

@end

@implementation SUCeritifcate

@synthesize name;

- (instancetype)initWithCertificate:(SecCertificateRef)aCertificate
{
    self = [super init];
    if (self)
    {
        if (aCertificate == NULL)
        {
            return nil;
        }

        self.certificate = (SecCertificateRef)CFRetain(aCertificate);
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

        self.certificate = result;
    }
    return self;
}

- (void)dealloc
{
    if (self.certificate)
    {
        CFRelease(self.certificate);
    }
}

#pragma mark -

- (NSString *)name
{
    if (name == nil)
    {
        CFStringRef nameRef = NULL;
        if ((SecCertificateCopyCommonName(self.certificate, &nameRef) == noErr) && nameRef != NULL)
        {
            name = CFBridgingRelease(nameRef);
        }
    }
    return name;
}

@end
