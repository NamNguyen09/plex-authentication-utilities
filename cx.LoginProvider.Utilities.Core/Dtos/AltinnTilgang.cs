namespace cx.LoginProvider.Utilities.Core.Dtos
{
    [Serializable]
    public partial class AltinnTilgang
    {
        public Subject Subject { get; set; }
        public List<Right> Rights { get; set; }
    }

    [Serializable]
    public partial class Right
    {
        public int RightId { get; set; }
        public string RightType { get; set; }
        public string ServiceCode { get; set; }
        public int ServiceEditionCode { get; set; }
        public string Action { get; set; }
        public string RightSourceType { get; set; }
    }

    [Serializable]
    public partial class Subject
    {
        public string Name { get; set; }
        public string Type { get; set; }
    }
}