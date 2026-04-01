{
  description = "Measure character-echo latency and bandwidth for an interactive ssh session";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in
    {
      formatter.${system} = pkgs.nixfmt-tree;

      packages.${system} = {
        default = pkgs.stdenv.mkDerivation {
          pname = "sshping";
          version = "master";

          outputs = [ "out" "man" ];

          src = self;

          buildInputs = with pkgs; [ libssh perl ];

          buildPhase = ''
            make bin/sshping
            make doc/sshping.8.gz
          '';

          installPhase = ''
            install -Dm755 bin/sshping $out/bin/sshping
            install -Dm644 doc/sshping.8.gz $man/share/man/man8/sshping.8.gz
          '';
      
          meta = {
            homepage = "https://github.com/spook/sshping";
            description = "Measure character-echo latency and bandwidth for an interactive ssh session";
            license = pkgs.lib.licenses.mit;
            platforms = pkgs.lib.platforms.unix;
            maintainers = with pkgs.lib.maintainers; [ spook ];
            outputsToInstall = [ "out" "man" ];
            mainProgram = "sshping";
          };
        };
      };
    };
}
