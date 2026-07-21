#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// A tiny public API used to prove that DemoFramework is linked and embedded.
@interface DLDemoMessage : NSObject

+ (NSString *)fixedString;

@end

NS_ASSUME_NONNULL_END
