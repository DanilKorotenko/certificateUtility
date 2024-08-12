//
//  SUCeritifcate.h
//  certificateUtility
//
//  Created by Danil Korotenko on 8/12/24.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SUCeritifcate : NSObject

- (instancetype)initWithCertificate:(SecCertificateRef)aCertificate;
- (instancetype)initWithPath:(NSString *)aPath;

@property (readonly) NSString *name;
@property (readonly) SecCertificateRef certificateRef;

- (OSStatus)setTrustSettings;

@end

NS_ASSUME_NONNULL_END
