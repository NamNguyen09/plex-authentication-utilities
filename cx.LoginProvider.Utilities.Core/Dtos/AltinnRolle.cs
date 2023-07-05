namespace cx.LoginProvider.Utilities.Core.Dtos
{
    [Serializable]
    public partial class AltinnRolle
    {
        public int RoleDefinitionId { get; set; }
        public string RoleType { get; set; }
        public string RoleName { get; set; }
        public string RoleDescription { get; set; }
    }
}