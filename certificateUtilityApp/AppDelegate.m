//
//  AppDelegate.m
//  certificateUtilityApp
//
//  Created by Danil Korotenko on 9/18/24.
//

#import "AppDelegate.h"

#import "../SecurityUtilities/SUCeritifcate.h"
#import "../SecurityUtilities/SUKeychain.h"

@interface AppDelegate ()

@property (strong) IBOutlet NSWindow *window;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    NSString *certificatePath = [[NSBundle bundleForClass:[self class]]
        pathForResource:@"testCertificate" ofType:@"der"];
    SUCeritifcate *certificate = [[SUCeritifcate alloc] initWithPath:certificatePath];

    if (!certificate)
    {
        NSLog(@"No certificate");
        return;
    }

    SUKeychain *keychain = [SUKeychain loginKeychain];
    if (!keychain)
    {
        NSLog(@"No keychain");
        return;
    }

    if (![keychain containsCertificate:certificate])
    {
        OSStatus err = [keychain addCertificate:certificate];
        if (err != noErr)
        {
            NSLog(@"SecCertificateAddToKeychain failure. Error: %d", err);
        }
    }
    else
    {
        NSLog(@"Certificate already in keychain");
    }

    OSStatus err = [certificate installTrustSettingsForUser];
    if (err != noErr)
    {
        NSLog(@"SecTrustSettingsSetTrustSettings failure. Error: %d", err);
    }

    [NSApp terminate:nil];
}

- (void)applicationWillTerminate:(NSNotification *)aNotification
{

}

- (BOOL)applicationSupportsSecureRestorableState:(NSApplication *)app
{
    return YES;
}

@end
