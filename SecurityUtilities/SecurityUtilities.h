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

#pragma once

#include <string>
#include <vector>

bool areCertificatesInSystemKeychain(const std::string &aDerFolder, std::string &errorDescription);
bool areCertificatesInSystemKeychainAndAdminTrusted(const std::vector<std::string> &aHashes,
    std::string &errorDescription);

bool addCertificatesToCommonKeychain(const std::string &aDerFolder, std::string &errorDescription);

bool checkCertificates(const std::vector<std::string>& aHashes, std::string &errorDescription);

bool deleteCertificates(const std::vector<std::string>& aHashes, std::string &errorDescription);
