using System;
using System.Collections.Generic;

namespace cx.Authentication.Utilities.Dtos
{
    [Serializable]
    public class FeideGroup
    {
        public string Id { get; set; }
        public string DisplayName { get; set; }
        public List<string> OrgType { get; set; }
        public string NorEduOrgNIN { get; set; }
    }
}
