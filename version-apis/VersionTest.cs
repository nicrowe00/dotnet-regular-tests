using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Xunit;
using Xunit.Abstractions;

namespace DotNetCoreVersionApis
{
    public class VersionTest
    {
        public static readonly int MAX_DOTNET_MAJOR_VERSION = 10;

        private readonly ITestOutputHelper _output;

        public VersionTest(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public void EnvironmentVersion()
        {
            var version = Environment.Version;
            _output.WriteLine($"Environment.Version: {version}");
            Assert.InRange(version.Major, 3, MAX_DOTNET_MAJOR_VERSION);
        }

        [Fact]
        public void RuntimeInformationFrameworkDescription()
        {
            var description = RuntimeInformation.FrameworkDescription;
            _output.WriteLine($"RuntimeInformation.FrameworkDescription: {description}");
            Assert.StartsWith(".NET", description);
        }

        [Theory]
        [InlineData("coreclr", typeof(object))]
        [InlineData("corefx", typeof(Uri))]
        public void CommitHashesAreAvailable(string repo, Type type)
        {
            _output.WriteLine($"Testing commit hashes for {repo}");

            var attributes = (AssemblyInformationalVersionAttribute[])type.Assembly.GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute),false);
            var versionAttribute = attributes[0];
            _output.WriteLine($"AssemblyInformationVersionAttribute: {versionAttribute.InformationalVersion}");

            string[] versionParts = versionAttribute.InformationalVersion.Split("+");
            Assert.Equal(2, versionParts.Length);

            string fullVersion = versionParts[0];
            string plainVersion = fullVersion.Split("-")[0];

            Assert.Matches(new Regex("\\d+(\\.\\d)+"), plainVersion);

            bool okay = Version.TryParse(plainVersion, out Version parsedVersion);
            Assert.True(okay);
            Assert.InRange(parsedVersion.Major, 3, MAX_DOTNET_MAJOR_VERSION);

            var commitId = versionParts[1];
            Regex commitRegex = new Regex("[0-9a-fA-F]{40}");

            Assert.Matches(commitRegex, commitId);
        }
    }
}
