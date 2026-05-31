{
  description = "INK transparency witness reference implementation";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {nixpkgs, ...}: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.mkShell {
        packages = [pkgs.nodejs_24 pkgs.git pkgs.gitleaks];
        shellHook = ''
          cat <<'BANNER'

            INK transparency witness
            Reference implementation of the third-party witness role

          BANNER
        '';
      };
    });
  };
}
