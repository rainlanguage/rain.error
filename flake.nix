{
  description = "Flake for development workflows.";

  inputs = {
    rainix.url =
      "github:rainprotocol/rainix?rev=4e87c16f3abcb4e9e309609f452669f5a85bb558";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, flake-utils, rainix }:
    flake-utils.lib.eachDefaultSystem (system: {
      packages = rainix.packages.${system};
      devShells = rainix.devShells.${system};
    });
}
