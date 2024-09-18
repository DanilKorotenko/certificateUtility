//
//  SUKeychain.h
//  certificateUtility
//
//  Created by Danil Korotenko on 8/12/24.
//

#import <Foundation/Foundation.h>

#import "SUCeritifcate.h"

NS_ASSUME_NONNULL_BEGIN

@interface SUKeychain : NSObject

+ (SUKeychain *)systemKeychain;
+ (SUKeychain *)loginKeychain;
+ (SUKeychain *)commonKeychain;
+ (OSStatus)deleteCertificate:(SUCeritifcate *)aCertificate;

- (BOOL)containsCertificate:(SUCeritifcate *)aCertificate;
- (SUCeritifcate *)findCertificateBySHA1:(NSString *)aSHA1;

- (OSStatus)addCertificate:(SUCeritifcate *)aCertificate;

@end

NS_ASSUME_NONNULL_END
