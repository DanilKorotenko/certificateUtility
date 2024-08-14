// *=================================================================
// * GTB Technologies Proprietary
// * Copyright 2024 GTB Technologies, Inc.
// * UNPUBLISHED WORK
// * This software is the confidential and proprietary information of
// * GTB Technologies, Inc. ("Proprietary Information"). Any use,
// * reproduction, distribution or disclosure of the software or
// * Proprietary Information, in whole or in part, must comply with
// * the terms of the license agreement, nondisclosure agreement
// * or contract entered into with GTB Technologies, Inc. providing
// * access to this software.
// * @author Danil Korotenko<___EMAIL___>
// *==================================================================
//

#import "SecurityUtilities.h"

#import <Foundation/Foundation.h>

#import "../AuthorizationUtilities/AUAuthorization.h"
#import "SUKeychain.h"

bool installCertificates(const std::string &aDerFolder, const std::string &aLogin,
    const std::string &aPass, std::string &errorDescription)
{
    NSString *derFolderPath = [NSString stringWithUTF8String:aDerFolder.c_str()];
    NSURL *derFolderURL = [NSURL fileURLWithPath:derFolderPath];
    NSError *error = nil;
    NSArray *fileURLs = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:derFolderURL
        includingPropertiesForKeys:@[NSURLIsRegularFileKey] options:0 error:&error];

    if (fileURLs.count == 0)
    {
        errorDescription = "No certificates found.";
        return false;
    }

    SUKeychain *keychain = [[SUKeychain alloc] initSystemKeychain];
    if (!keychain)
    {
        errorDescription = "No keychain";
        return false;
    }

    __block NSString *internalErrorDescription = nil;

    OSStatus myStatus = executeTrustSettingsAdminAuthorizedBlock(aLogin.c_str(), aPass.c_str(),
        ^{
            for (NSURL *fileURL in fileURLs)
            {
                SUCeritifcate *certificate = [[SUCeritifcate alloc] initWithPath:fileURL.path];

                if (!certificate)
                {
                    internalErrorDescription = [NSString stringWithFormat:
                        @"Cannot read certificate: %@", fileURL.path];
                    break;
                }

                OSStatus err = noErr;

                if (![keychain containsCertificate:certificate])
                {
                    err = [keychain addCertificate:certificate];
                    if (err != noErr)
                    {
                        internalErrorDescription = [NSString stringWithFormat:
                            @"SecCertificateAddToKeychain failure. Error: %d", err];
                        break;
                    }
                }

                if (!certificate.isTrusted)
                {
                    err = [certificate installAdminTrustSettings];
                    if (err != noErr)
                    {
                        internalErrorDescription = [NSString stringWithFormat:
                            @"SecTrustSettingsSetTrustSettings failure. Error: %d", err];
                        break;
                    }
                }
            }
        });

    if (myStatus != noErr)
    {
        internalErrorDescription = @"Something went wrong with authorization.";
    }

    if (internalErrorDescription)
    {
        errorDescription = std::string([internalErrorDescription UTF8String]);
    }

    return internalErrorDescription == nil;
}
