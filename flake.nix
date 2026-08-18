{
  description = "INK transparency witness reference implementation";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      # Wrangler, vitest and typescript are pinned in package.json, so the
      # shell supplies the runtime they all sit on and nothing more.
      default = pkgs.mkShell {
        packages = [pkgs.nodejs_24 pkgs.git pkgs.gitleaks];
        shellHook = ''
          cat <<'BANNER'

            INK transparency witness
            Reference implementation of the third-party witness role

            npm ci && npm test && npm run typecheck

          BANNER
        '';
      };
    });

    # `nix flake check` builds the shell. The suite itself needs the npm
    # dependency tree, which the sandbox has no network to fetch, so CI
    # runs npm ci, test and typecheck through this same shell.
    checks = forAllSystems (system: {
      devShell = self.devShells.${system}.default;
    });

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.alejandra);
  };
}
