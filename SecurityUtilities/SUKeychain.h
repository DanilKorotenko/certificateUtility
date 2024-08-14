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

- (instancetype)initSystemKeychain;

- (BOOL)containsCertificate:(SUCeritifcate *)aCertificate;

- (OSStatus)addCertificate:(SUCeritifcate *)aCertificate;

@end

NS_ASSUME_NONNULL_END
