{
  description = "sss vault-integration devShell — pinned openbao + process-compose + jq";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      # Systems for which the vault-it devShell is built.
      # The Rust toolchain is NOT included — it stays ambient on the host so
      # the pinned flake.lock governs only the OpenBao + process-compose + jq
      # binaries, not the compiler.
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      forAllSystems = f:
        builtins.listToAttrs (map (system: {
          name = system;
          value = f system;
        }) supportedSystems);

    in {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in {
          # vault-it: the devShell used by the Phase 47-05 live integration tier.
          #
          # Pinned by flake.lock (content-addressed nixpkgs rev).  The lock is
          # committed so the exact OpenBao 2.5.4 + process-compose 1.110.0 +
          # jq 1.8.1 binaries are reproducible across machines and CI runs.
          # This is the nix analogue of the digest-pinned base-image convention
          # (REM-45) — a floating, unlocked input is not acceptable.
          #
          # Invocation:
          #   nix develop .#vault-it --command cargo test --features vault --test vault_integration
          #
          # openbao 2.5.4  — MPL-2.0, Linux Foundation OpenBao fork; API-identical
          #                   to HashiCorp Vault for the KV-v2 + AppRole + sys/health
          #                   surfaces sss exercises.  Binary: `bao`.
          # process-compose 1.110.0 — MIT; manages the OpenBao dev-server lifecycle
          #                   (start/stop/readiness-probe) without a container runtime.
          # jq 1.8.1        — MIT; used by any shell-level diagnostic scripts.
          vault-it = pkgs.mkShell {
            packages = [
              pkgs.openbao
              pkgs.process-compose
              pkgs.jq
            ];
          };
        });
    };
}
