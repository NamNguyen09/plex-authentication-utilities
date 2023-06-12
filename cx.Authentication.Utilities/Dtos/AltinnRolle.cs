using System;

namespace cx.Authentication.Utilities.Dtos
{
    [Serializable]
    public class AltinnRolle
    {
        public int RoleDefinitionId { get; set; }
        public string RoleType { get; set; }
        public string RoleName { get; set; }
        public string RoleDescription { get; set; }
    }
}