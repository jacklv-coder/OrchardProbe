#import <DemoFramework/DLDemoMessage.h>

extern void oprobe_framework_anchor(void);

@implementation DLDemoMessage

+ (NSString *)fixedString {
    oprobe_framework_anchor();
    return @"Hello from the embedded Objective-C framework.";
}

@end
