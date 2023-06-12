﻿using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace cx.Authentication.Utilities.Dtos
{
    [Serializable]
    public class OidcModel
    {
        public List<Claim> Claims { get; set; }
        public string UserInfo { get; set; }
        public string ApiUserInfo { get; set; }
        public string GroupInfo { get; set; }
    }
}