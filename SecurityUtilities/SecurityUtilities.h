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

bool installCertificates(const std::string &aDerFolder, const std::string &aLogin,
    const std::string &aPass, std::string &errorDescription);
