
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (HexString)

+ (NSData *)dataWithHexString:(NSString *)hex;

@property (readonly) NSString *hexString;

@end

NS_ASSUME_NONNULL_END
