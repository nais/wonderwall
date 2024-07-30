{
  description = "Unleasherator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {self, ...} @ inputs:
    inputs.flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import inputs.nixpkgs {localSystem = {inherit system;};};
      name = "wonderwall";
      wonderwall = pkgs.buildGoModule {
        inherit name;
        # nativeBuildInputs = with pkgs; [
        #   golangci-lint
        # ];
        # GOLANGCI_LINT = "${pkgs.golangci-lint}";
        src = inputs.gitignore.lib.gitignoreSource ./.;
        vendorHash = "sha256-3RqVAgA9iJhX0mbwlVMH+NSUz3H9Uobgs8zm1x9fb1o="; # nixpkgs.lib.fakeSha256;
      };
    in {
      devShells.default = pkgs.mkShell {
        inputsFrom = [wonderwall];
      };
      packages = {
        inherit wonderwall;
        docker = let
          imageRef = "europe-north1-docker.pkg.dev/nais-management-233d";
          teamName = "nais";
          dockerTag =
            if pkgs.lib.hasAttr "rev" self
            then "${builtins.toString self.revCount}-${self.shortRev}"
            else "gitDirty";
        in
          pkgs.dockerTools.buildImage {
            config = {Entrypoint = ["${wonderwall}/bin/${name}"];};
            name = "${imageRef}/${teamName}/${name}";
            tag = "${dockerTag}";
          };
      };
      packages.default = wonderwall;
      formatter = pkgs.alejandra;
    });
}
