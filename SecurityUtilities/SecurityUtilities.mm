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
#import "../IdentityUtilities/IUIdentity.h"

#import "SUKeychain.h"

#include <vector>

bool areCertificatesInSystemKeychain(const std::string &aDerFolder, std::string &errorDescription)
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

    SUKeychain *keychain = [SUKeychain systemKeychain];
    if (!keychain)
    {
        errorDescription = "No keychain";
        return false;
    }

    NSString *internalErrorDescription = nil;

    for (NSURL *fileURL in fileURLs)
    {
        SUCeritifcate *certificate = [[SUCeritifcate alloc] initWithPath:fileURL.path];
        if (!certificate)
        {
            internalErrorDescription = [NSString stringWithFormat:
                @"Cannot read certificate: %@", fileURL.path];
            break;
        }

        if (![keychain containsCertificate:certificate])
        {
            internalErrorDescription = [NSString stringWithFormat:
                @"Certificate not in system keychain: %@", certificate.name];
            break;
        }
    }

    if (internalErrorDescription)
    {
        errorDescription = std::string([internalErrorDescription UTF8String]);
    }
    return internalErrorDescription == nil;
}

bool areCertificatesInSystemKeychainAndAdminTrusted(const std::vector<std::string> &aHashes,
    std::string &errorDescription)
{
    NSString *internalErrorDescription = nil;

    SUKeychain *systemKeychain = [SUKeychain systemKeychain];

    for (std::string sha1Item: aHashes)
    {
        NSString *sha1 = [[NSString alloc] initWithUTF8String:sha1Item.c_str()];
        SUCeritifcate *certificate = [systemKeychain findCertificateBySHA1:sha1];
        if (!certificate)
        {
            internalErrorDescription = [NSString stringWithFormat:@"Certificate not found: %@", sha1];
            break;
        }

        if (!certificate.isAdminTrusted)
        {
            internalErrorDescription = [NSString stringWithFormat:@"certificate not admin trusted: %@",
                certificate.name];
            break;
        }
    }

    if (internalErrorDescription)
    {
        errorDescription = std::string([internalErrorDescription UTF8String]);
    }
    return internalErrorDescription == nil;

}

bool addCertificatesToCommonKeychain(const std::string &aDerFolder, std::string &errorDescription)
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

    SUKeychain *keychain = [SUKeychain commonKeychain];
    if (!keychain)
    {
        errorDescription = "No common keychain";
        return false;
    }

    NSString *internalErrorDescription = nil;

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
                    @"Add certificate To common Keychain failure. Error: %d", err];
                break;
            }
        }
    }

    if (internalErrorDescription)
    {
        errorDescription = std::string([internalErrorDescription UTF8String]);
    }
    return internalErrorDescription == nil;
}

// certificate must be already in keychain
bool checkCertificates(const std::vector<std::string> &aHashes, std::string &errorDescription)
{
    NSString *internalErrorDescription = nil;

    SUKeychain *commonKeychain = [SUKeychain commonKeychain];

    for (std::string sha1Item: aHashes)
    {
        NSString *sha1 = [[NSString alloc] initWithUTF8String:sha1Item.c_str()];
        SUCeritifcate *certificate = [commonKeychain findCertificateBySHA1:sha1];
        if (!certificate)
        {
            internalErrorDescription = [NSString stringWithFormat:@"Certificate not found: %@", sha1];
            break;
        }

        if (!certificate.isAnyTrusted)
        {
            OSStatus status = [certificate installTrustSettingsForUser];
            if (status != noErr)
            {
                internalErrorDescription = [NSString stringWithFormat:@"Error on install trust settings: %d", status];
                break;
            }
        }
    }

    if (internalErrorDescription)
    {
        errorDescription = std::string([internalErrorDescription UTF8String]);
    }
    return internalErrorDescription == nil;
}

// certificate must be already in keychain
bool deleteCertificates(const std::vector<std::string> &aHashes, std::string &errorDescription)
{
    NSString *internalErrorDescription = nil;

    SUKeychain *commonKeychain = [SUKeychain commonKeychain];

    for (std::string sha1Item: aHashes)
    {
        NSString *sha1 = [[NSString alloc] initWithUTF8String:sha1Item.c_str()];
        SUCeritifcate *certificate = [commonKeychain findCertificateBySHA1:sha1];
        if (certificate)
        {
            OSStatus status = [SUKeychain deleteCertificate:certificate];
            if (status != noErr)
            {
                internalErrorDescription = [NSString stringWithFormat:@"Error on delete certificate: %d", status];
                break;
            }
        }
    }

    if (internalErrorDescription)
    {
        errorDescription = std::string([internalErrorDescription UTF8String]);
    }
    return internalErrorDescription == nil;
}
