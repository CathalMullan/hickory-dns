{
  description = "hickory-dns";

  inputs = {
    nixpkgs = {
      url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";

      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  # nix flake show
  outputs =
    {
      nixpkgs,
      rust-overlay,
      ...
    }:

    let
      perSystem = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;

      systemPkgs = perSystem (
        system:

        import nixpkgs {
          inherit system;

          overlays = [
            rust-overlay.overlays.default
          ];
        }
      );

      perSystemPkgs = f: perSystem (system: f (systemPkgs.${system}));
    in
    {
      devShells = perSystemPkgs (pkgs: {
        # nix develop
        default = pkgs.mkShell {
          name = "hickory-dns-shell";

          env = {
            # Nix
            NIX_PATH = "nixpkgs=${nixpkgs.outPath}";

            # Rust
            RUSTFLAGS = "-C target-cpu=native -C link-arg=-fuse-ld=mold";
            RUST_BACKTRACE = "0";
          };

          buildInputs = with pkgs; [
            # Rust
            (rust-bin.stable.latest.minimal.override {
              extensions = [
                "clippy"
                "llvm-tools"
                "rust-analyzer"
                "rust-docs"
                "rust-src"
                "rustfmt"
              ];
            })
            mold
            taplo
            just
            cargo-shear
            cargo-workspaces

            # AWS LC
            cmake
            perl
            go

            # Spellchecking
            typos
            typos-lsp

            # Nix
            nixfmt
            nixd
            nil
          ];
        };
      });
    };
}
