//
//  AUAuthorization.h
//  certificateUtility
//
//  Created by Danil Korotenko on 8/12/24.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

OSStatus executeTrustSettingsAdminAuthorizedBlock(const char *aLogin, const char *aPassword, void (^aBlock)(void));

NS_ASSUME_NONNULL_END
