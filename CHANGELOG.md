<a name="unreleased"></a>
## [Unreleased]


<a name="v4.0.0-rc.4"></a>
## [v4.0.0-rc.4] - 2020-09-28
### *
- [74efdf6](https://github.com/quay/clair/commit/74efdf6b51e3e625ca9f122e7aa88e88f4708a68): update roadmap
 - Fixes [#626](https://github.com/quay/clair/issues/626)- [ce15f73](https://github.com/quay/clair/commit/ce15f73501b758b3d24e06753ce62123d0a36920): gofmt -s
- [5caa821](https://github.com/quay/clair/commit/5caa821c80a4efa2986728d6f223552b44f6ce15): remove bzr dependency
- [033cae7](https://github.com/quay/clair/commit/033cae7d358b2f7b866da7d9be3367d902cdf035): regenerate bill of materials
- [1f5bc26](https://github.com/quay/clair/commit/1f5bc26320bc58676d88c096404a8503dca7a4d8): rename example config
### .Github
- [9b1f205](https://github.com/quay/clair/commit/9b1f2058338b8aeaa5441091b4920731235f1353): add stale and issue template enforcement
### API
- [0151dba](https://github.com/quay/clair/commit/0151dbaef81cae54aa95dd8abf36d58414de2b26): change api port to api addr, rename RunV2 to Run.
 - Fixes [#446](https://github.com/quay/clair/issues/446)- [a378cb0](https://github.com/quay/clair/commit/a378cb070cb9ec56f363ec08adb8e023bfb3994e): drop v1 api, changed v2 api for Clair v3.
### All
- [fbbffcd](https://github.com/quay/clair/commit/fbbffcd2c2a34d8a6128a06a399234b444c74d09): add opentelemetry hooks
### Api
- [69c0c84](https://github.com/quay/clair/commit/69c0c84348c74749cd1d12ee4e4959991621a59d): Rename detector type to DType
- [48427e9](https://github.com/quay/clair/commit/48427e9b8808f86929ffb905952395c91644f04e): Add detectors for RPC
- [dc6be5d](https://github.com/quay/clair/commit/dc6be5d1b073d87b2405d84d33f5bb5f6ced490e): remove handleShutdown func
- [30644fc](https://github.com/quay/clair/commit/30644fcc01df7748d8e2ae15c427f01702dd4e90): remove dependency on graceful
- [58022d9](https://github.com/quay/clair/commit/58022d97e3ec7194e89522c9adb866a85c704378): renamed V2 API to V3 API for consistency.
- [c6f0eaa](https://github.com/quay/clair/commit/c6f0eaa3c82197f15371b4d2c8af686d8a7a569f): fix remote addr shows reverse proxy addr problem
- [a4edf38](https://github.com/quay/clair/commit/a4edf385663b2e412e1fd64f7d45e1ee01749798): v2 api with gRPC and gRPC-gateway
 - Fixes [#98](https://github.com/quay/clair/issues/98)### Api,Database
- [a75b8ac](https://github.com/quay/clair/commit/a75b8ac7ffe3ccd7ff9c4718e547c6c5103e9747): updated version_format documentation.
 - Fixes [#514](https://github.com/quay/clair/issues/514)### Api/V3
- [32b11e5](https://github.com/quay/clair/commit/32b11e54eb287ed0d686ba72fe413b773b748a38): Add feature type to API feature
- [f550dd1](https://github.com/quay/clair/commit/f550dd16a01edc17de0e3c658c5f7bc25639a0a1): remove dependency on google empty message
- [d7a751e](https://github.com/quay/clair/commit/d7a751e0d4298442883fde30ee37c529b2bb3719): prototool format
### Api/V3/Clairpb
- [6b9f668](https://github.com/quay/clair/commit/6b9f668ea0b657526b35008f8efd9c8f0a46df9b): document and regenerate protos
- [ec5014f](https://github.com/quay/clair/commit/ec5014f8a13605458faf1894bb905f2123ded0a7): regen protobufs
- [389b6e9](https://github.com/quay/clair/commit/389b6e992790f6e28b77ca5979c0589e43dbe40a): generate protobufs in docker
### Auth
- [f00698b](https://github.com/quay/clair/commit/f00698ba36ac1b88bb77f21ca4e9d99caf28b0b1): psk fixup
- [29ed5f6](https://github.com/quay/clair/commit/29ed5f60b8dfe882f95aae7d61b1e373e06a2145): use better guesses for "aud" claim
- [6932ad3](https://github.com/quay/clair/commit/6932ad3264c3b1760ef46d094b25c12664cee1cc): add keyserver algorithm allowlist
- [dc91ec9](https://github.com/quay/clair/commit/dc91ec9e96db7ab7eee853c89a768ac0414a8f9a): test multiple PSK signing algorithms
### CODEOWNERS
- [f20a72c](https://github.com/quay/clair/commit/f20a72c34ef80b4c1dee7b9984aa713f82e6c342): add Louis
- [abf6e74](https://github.com/quay/clair/commit/abf6e74790294bb765a68765afa9d8e73c3fab22): init
### Chore
- [d141c5c](https://github.com/quay/clair/commit/d141c5cac5d4e4b13f614ebedb89c99ee3ebf8b0): bump claircore to v0.1.9
- [cd34ea9](https://github.com/quay/clair/commit/cd34ea9e264a8690bb88866f96a407949b14b0a1): remove unused files
- [a38501b](https://github.com/quay/clair/commit/a38501b3aabb92b244f51268e565c1763f62622b): claircore bump to v0.1.8
- [f41fba5](https://github.com/quay/clair/commit/f41fba5087f0ff5ebcd3724cb22975a5547fa572): bump cc and golang container
### Cicd
- [c447bcc](https://github.com/quay/clair/commit/c447bcce4ce4546228b91559c85108ec7a3194af): commit check regexp fix
- [54ee2d2](https://github.com/quay/clair/commit/54ee2d25cd05593edc38a94103bef459f6219c4b): change log generation and releases
### Clair
- [fa95f5d](https://github.com/quay/clair/commit/fa95f5d80c86f3e916661156f99dac6fcc91a3bb): bump claircore version
- [42b1ba9](https://github.com/quay/clair/commit/42b1ba9f91f9174397280152eca5a0096342019e): use Etag header to communicate indexer state change
- [fd5993f](https://github.com/quay/clair/commit/fd5993f9765cc23355e5895105a15b71e5eb3156): add "mode" argument
- [4091329](https://github.com/quay/clair/commit/409132958e0538046e3481d3197e192316b06d91): change version information
- [8cbddd1](https://github.com/quay/clair/commit/8cbddd187e7065315417ca2f86a5e261f3d92651): better introspection server defaults
- [c097454](https://github.com/quay/clair/commit/c097454c182daa68427918d0ba2fe24bbdf6ed71): logging and introspection setup
- [a003aa4](https://github.com/quay/clair/commit/a003aa414ead82a32b24a977e301e5697718ec43): add configuration for introspection
- [d9db7c1](https://github.com/quay/clair/commit/d9db7c153ce80d3d47bbb342bd6ef873bc2954b4): use "Updaters" config option
- [48daeae](https://github.com/quay/clair/commit/48daeaeacc5a1444a07cc6ddc20b4b800d8b43be): fix header casing
- [fb28e56](https://github.com/quay/clair/commit/fb28e569da21f847c7bbc2f97807485ea007e698): remove os.Exit call on clean shutdown
- [8039e1c](https://github.com/quay/clair/commit/8039e1c95f56353e47aaa5ed66b80244ac2d2cad): add authorization checking
- [1b41336](https://github.com/quay/clair/commit/1b41336265126c23b152d18c28ea6e0fd3d6baf8): update claircore to 0.0.14
- [791610f](https://github.com/quay/clair/commit/791610f1c893fc76d6fcf350a7383a2479aa723a): remove goautoneg
- [7b6ef7d](https://github.com/quay/clair/commit/7b6ef7da8c125111ec37fe61206dce1ee25408ec): reset writers when pulled from pool
- [ad73d74](https://github.com/quay/clair/commit/ad73d747fcc6c674752eaf5ae7ccdcb6fa4daead): remove vendor directory
- [00eff59](https://github.com/quay/clair/commit/00eff59af580893d3e045333fa095d3507a528f1): rewrite imports
- [1f2ceeb](https://github.com/quay/clair/commit/1f2ceeb8f7fcf9e8ce94206f76a8b610b84424ca): create module
- [c6497dd](https://github.com/quay/clair/commit/c6497dda0a95a3309dc649761243250634a31d40): Fix namespace update logic
- [465687f](https://github.com/quay/clair/commit/465687fa94b4e9fe00e0ba1190989d0d454c14ab): Add more logging on ancestry cache hit
- [5b23764](https://github.com/quay/clair/commit/5b2376498bbc0ea0a893754887defce4daa59daa): Use builder pattern for constructing ancestry
- [0283240](https://github.com/quay/clair/commit/028324014ba3b7111e4e4533d6a8d4d99bb1fd72): Implement worker detector support
### Clair Logic, Extensions
- [fb32dcf](https://github.com/quay/clair/commit/fb32dcfa58077dadd8bfbf338c4aa342d5e9ef85): updated mock tests, extensions, basic logic
### Clairctl
- [c0a9c0b](https://github.com/quay/clair/commit/c0a9c0b7d336de1377eb3cb14fb8a1af97a49b3e): init default updaters
- [050bc2d](https://github.com/quay/clair/commit/050bc2d1f44824f2573c6219a21d3a00e1ce7a76): add import and export commands
- [2e68178](https://github.com/quay/clair/commit/2e6817881eed93af469abd7e16839961aa812469): remove log.Lmsgprefix
- [0282f68](https://github.com/quay/clair/commit/0282f68bf381a5b0a592079819e38b3d88296f92): report command
- [f1c4798](https://github.com/quay/clair/commit/f1c4798bb10292fe1f14d71691ab33d4ea5a2ae9): start on clair cli tool
### Client
- [32b327f](https://github.com/quay/clair/commit/32b327f701f579d595b5b94cb7ca08813e366101): fix nil check
- [1ba6891](https://github.com/quay/clair/commit/1ba68911163afb001cd89cf84862506f008edcf4): add differ and refactor client
### Cmd/Clair
- [b20482e](https://github.com/quay/clair/commit/b20482e0aebcf2cc67f61e8ff821ddcdffc53ac7): document constants
### Config
- [03cf755](https://github.com/quay/clair/commit/03cf7555ab13856fddd5b71e1374d1f7281a800e): update matcher configurables
- [daf2e29](https://github.com/quay/clair/commit/daf2e296e9d2bc2b4d40f18ff00937829f469c04): reorganize updater configuration
- [3ccc6e0](https://github.com/quay/clair/commit/3ccc6e03be0ce1b6c439d5c0649ee785dc7c559f): add support for per-scanner configuration
- [a93271b](https://github.com/quay/clair/commit/a93271b3be48ebe617363751d64e26840678583e): implement base64 -> []byte conversion ([#984](https://github.com/quay/clair/issues/984))
 -  [#984](https://github.com/quay/clair/issues/984)- [2ed3c2c](https://github.com/quay/clair/commit/2ed3c2c800bb9639618a86f33916625b0a595f49): rework auth config
- [b2666e5](https://github.com/quay/clair/commit/b2666e57202d7c690a40d7c86975c13e0b3db56e): set a canonical default port
- [4f23269](https://github.com/quay/clair/commit/4f232698b0178ef9d1a3cde01b6ff40e47659cfa): add updaters and tracing options
- [162e8cd](https://github.com/quay/clair/commit/162e8cdafc66be28b021f83da736a2b612ddda99): enable suse updater
- [0609ed9](https://github.com/quay/clair/commit/0609ed964b0673806462a24147e6028da85d8a38): removed worker config
### Contrib
- [76b9f8e](https://github.com/quay/clair/commit/76b9f8ea05b110d1ff659964fc9126824ec28b17): replace old k8s manifests with helm
- [ac1cdd0](https://github.com/quay/clair/commit/ac1cdd03c9e31ddaea627e076704f38a0d4719fb): move grafana and compose here
### Contrib/Helm/Clair
- [13be17a](https://github.com/quay/clair/commit/13be17a69082d30996d53d3087b7265007bae555): fix the ingress template
### Convert
- [f2ce832](https://github.com/quay/clair/commit/f2ce8325b975a15c977654d3be1084ad1e890bf3): return nil when detector is empty
### Database
- [506698a](https://github.com/quay/clair/commit/506698a4246e24bb3a72bd626d95bd47dc38beb8): add mapping for Ubuntu Eoan (19.10)
- [1ddc053](https://github.com/quay/clair/commit/1ddc0532e4be8dac02e171b986da51deaffbb636): Handle FindAncestryAndRollback datastore.Begin() error
 - Fixes [#828](https://github.com/quay/clair/issues/828)- [6617f56](https://github.com/quay/clair/commit/6617f560cc9ce90eece08aca29841827c72ca5c2): Rename affected type to feature type (for Amazon Linux updater)
- [3fafb73](https://github.com/quay/clair/commit/3fafb73c4fe0e9fbc03d1c5657b57ba0ca04c000): Split models.go into different files each contains one model
- [1b9ed99](https://github.com/quay/clair/commit/1b9ed99646e492a27e982ae34dea7c6fc7273c52): Move db logic to dbutil
- [961c7d4](https://github.com/quay/clair/commit/961c7d4680c58e3b01eedb4361a3fa57a1f9a904): add test for lock expiration
- [a4e7873](https://github.com/quay/clair/commit/a4e7873d1432b9b593f2e9dc44a02f2badea9002): make locks SOI & add Extend method
- [5fa1ac8](https://github.com/quay/clair/commit/5fa1ac89b9946f2e32ac666080b4f78ad1f9bbfa): Add StorageError type
- [f616753](https://github.com/quay/clair/commit/f61675355e7a296989e778f37257e6e416e6f208): Update feature model Remove source name/version fields Add Type field to indicate if it's binary package or source package
- [7dd989c](https://github.com/quay/clair/commit/7dd989c0f21bc5c4cb390f575dca9973829ef9ce): Rename affected Type to feature type
- [00eed77](https://github.com/quay/clair/commit/00eed77b451b8913771feef7a40067dd246d7872): Add feature_type database model
- [dd91597](https://github.com/quay/clair/commit/dd91597f19dae90e8b671d2c80004f0a28dc177c): remove FindLock from mock
- [399deab](https://github.com/quay/clair/commit/399deab1005b7c3541ad0dacb52bd7961b5167cc): remove FindLock()
- [300bb52](https://github.com/quay/clair/commit/300bb52696036dce96ee360f4431837e6ee452a2): add FindLock dbutil
- [4fbeb9c](https://github.com/quay/clair/commit/4fbeb9ced594b17aeee3e022f87ed7345376f232): add (Acquire|Release)Lock dbutils
- [6c682da](https://github.com/quay/clair/commit/6c682da3e138e0a7d09dadae7040d8cebba88e2b): add mapping for Ubuntu Cosmic (18.10)
- [a3f7387](https://github.com/quay/clair/commit/a3f7387ff146226f31a03906591cbb0d0e64cb44): Add FindKeyValue function wrapper
- [00fadfc](https://github.com/quay/clair/commit/00fadfc3e3da8c25b6c0c3f13d48017173a45a93): Add affected feature type
- [f759dd5](https://github.com/quay/clair/commit/f759dd54c028e8b39fd1e21c8c70ebda567aa7cd): Replace Parent Feature with source metadata
- [3fe894c](https://github.com/quay/clair/commit/3fe894c5ad7b33223be4a6d52bc0d88fc0fd3a18): Add parent feature pointer to Feature struct
- [a3e9b5b](https://github.com/quay/clair/commit/a3e9b5b55d13921b61e2f92a1ade9392b6e7d7a0): rename utility functions with commit/rollback
- [e657d26](https://github.com/quay/clair/commit/e657d26313b1b91fe4dab17298597119dc919cd2): move dbutil and testutil to database from pkg
- [db2db8b](https://github.com/quay/clair/commit/db2db8bbe8a17e10c9fb365196f88d552e70e91d): Update database model and interface for detectors
- [e160616](https://github.com/quay/clair/commit/e160616723643beff99363b7b385fd4b8ce6802a): Use LayerWithContent as Layer
- [ff93039](https://github.com/quay/clair/commit/ff9303905beb2e2f28d2a33e3fc232cd846b5963): changed Notification interface name
- [a5c6400](https://github.com/quay/clair/commit/a5c6400065a873f6ae14d50b73550dc07239d7bf): postgres implementation with tests.
### Database/Pgsql
- [4491bed](https://github.com/quay/clair/commit/4491bedf2e284007fa7f527bf264dc98c937d820): move token lib
### Datastore
- [57b146d](https://github.com/quay/clair/commit/57b146d0d808a29db9f299778fb5527cd0974b06): updated for Clair V3, decoupled interfaces and models
### Deployment
- [bc4c324](https://github.com/quay/clair/commit/bc4c3243c0e0bb952bb2e5d7a29d9e5d08e71962): use service prefix for simplified path routing
- [0fe5f73](https://github.com/quay/clair/commit/0fe5f7315c90bc5c0e984fa6de72b96c79dec27c): ubi8 based dockerfile
 -  [#198](https://github.com/quay/clair/issues/198)### Dockerfile
- [5a73cb4](https://github.com/quay/clair/commit/5a73cb49d64e839d7675979b5e3f348d94dd26a5): make -mod=vendor opportunisitic ([#999](https://github.com/quay/clair/issues/999))
 -  [#999](https://github.com/quay/clair/issues/999)- [33da12a](https://github.com/quay/clair/commit/33da12a3bb9a28fdbcc6302caa4212d38a2acbbb): run as unprivledged user by default
- [e56b95a](https://github.com/quay/clair/commit/e56b95aca0085067f91f90e3b32dab9d04e7fb48): use environment variables
- [33b3224](https://github.com/quay/clair/commit/33b3224df13b9c2aa8b0281f120997abce82eaf9): update for clair v4
### Dockerfile
- [2ca92d0](https://github.com/quay/clair/commit/2ca92d00754b1d1859e9d6f3169d67d6b96d6bee): bump Go to 1.13
### Dockerfile: Update To Alpine
- [de32b07](https://github.com/quay/clair/commit/de32b0728ccdbafb85988e2f87618c9d576fc87e): 3.11 for newest rpm
### Docs
- [d34acaf](https://github.com/quay/clair/commit/d34acaf54063d04979820a6be6e8c0181fc0fb65): update for v4
- [4f35fd0](https://github.com/quay/clair/commit/4f35fd0959cbfb2f7c195c45d17d1c90ca1b7390): rework mdbook
- [49b5621](https://github.com/quay/clair/commit/49b5621d738978c94e8d311775bba48a1daafc7e): fix typo in running-clair
- [9ee2ff4](https://github.com/quay/clair/commit/9ee2ff4877db15a5ad8ae24afcb8f02f0e8289cf): add troubleshooting about kernel packages
- [3f91bd2](https://github.com/quay/clair/commit/3f91bd2a9bc40bd7b6f4e5a5a8a533de383f3554): turn README into full articles
### Documentation
- [fe324a5](https://github.com/quay/clair/commit/fe324a58e6be8c36da74afcd5487d0da4a547d5b): start writing v4-specific docs
- [c1a58bf](https://github.com/quay/clair/commit/c1a58bf9224bbcd7e0f02ea4065650d220654f29): add new 3rd party tool
### Documentation
- [3e6896c](https://github.com/quay/clair/commit/3e6896c6a4e5cdd04d91927d762b332b62e1d4fe): fix links to presentations
 - Closes [#661](https://github.com/quay/clair/issues/661) - Closes [#665](https://github.com/quay/clair/issues/665) - Closes [#560](https://github.com/quay/clair/issues/560)### Driver
- [5c58575](https://github.com/quay/clair/commit/5c5857548d43fa866d46a4c98309b2dfa88be418): Add proxy support
### Drone
- [0fd9cd3](https://github.com/quay/clair/commit/0fd9cd3b59bd42ef0e508f0f415028a0ee8fa44f): remove broken drone CI
- [352f738](https://github.com/quay/clair/commit/352f73834e7bdef31dc5e3a715133f5c47947764): init
### Ext
- [25078ac](https://github.com/quay/clair/commit/25078ac838920e4010ecdbe4546af0d4b502dabd): add CleanAll() utility functions
- [081ae34](https://github.com/quay/clair/commit/081ae34af146365146cf4548a8a0afa293e15695): remove duplicate vectorValuesToLetters definition
- [4f0da12](https://github.com/quay/clair/commit/4f0da12b123ec543a58936c0f7226254e411cc00): pass through CVSSv3 impact and exploitability score
- [8efc3e4](https://github.com/quay/clair/commit/8efc3e40382287e88714fdcf634a79e6347b6157): remove unneeded use of init()
- [699d114](https://github.com/quay/clair/commit/699d1143e5ab2a673d0f83249f3268cfebaf3e57): fixup incorrect copyright year
- [b81e445](https://github.com/quay/clair/commit/b81e4454fbb7f3dcec4a2dd6064820bf0c6321f2): Parse CVSSv3 data from JSON NVD feed
- [14277a8](https://github.com/quay/clair/commit/14277a8f5d95799bb651c194785dd04e75a08ee1): Add JSON NVD parsing tests
- [aab46f5](https://github.com/quay/clair/commit/aab46f5658cf5a75262945033cb41d93af5f2131): Parse NVD JSON feed instead of XML
- [8d5a013](https://github.com/quay/clair/commit/8d5a0131c48d0812d1dd53b1af8e24ae4e51c4ba): Use SHA256 instead of SHA1 for fingerprinting
- [53bf19a](https://github.com/quay/clair/commit/53bf19aecfcccb367bc359a2dd6d7320fa4e4855): Lister and Detector returns detector info with detected content
### Ext/Featurefmt
- [1c40e7d](https://github.com/quay/clair/commit/1c40e7d01697f5680408f138e6974266c6530cb1): Refactor featurefmt testing code
### Ext/Featurefmt/Apk
- [2cc61f9](https://github.com/quay/clair/commit/2cc61f9fc0edc42d2c0fda71471208e3faba507d): Extract origin package information from database
### Ext/Featurefmt/Dpkg
- [4ac0466](https://github.com/quay/clair/commit/4ac046642ffea9fb60af455b9d22d19cd4408f32): Extract source package metadata
### Ext/Featurefmt/Rpm
- [a057e4a](https://github.com/quay/clair/commit/a057e4a943dc1a2dc1898b67435b05417725402e): Extract source package from rpm database
### Feature
- [90f5592](https://github.com/quay/clair/commit/90f5592095f74e9704193f4362c494571667b326): replace arrays with slices
### Featurefmt
- [34c2d96](https://github.com/quay/clair/commit/34c2d96b3685a927749536017add6538578fb2df): Extract PotentialNamespace
- [0e0d8b3](https://github.com/quay/clair/commit/0e0d8b38bba4c62552c98ad5b98242ddd2c3464b): Extract source packages and binary packages The featurefmt now extracts both binary packages and source packages from the package manager infos.
- [9561d62](https://github.com/quay/clair/commit/9561d623c29394dddca0823721d7d3622b3dec65): use namespace's versionfmt to specify listers
### Featurens
- [947a8aa](https://github.com/quay/clair/commit/947a8aa00c6f72a20e7fca63993dafaf3185fdc4): Ensure RHEL is correctly identified
 - Fixes [#436](https://github.com/quay/clair/issues/436)- [50437f3](https://github.com/quay/clair/commit/50437f32a1d7d609cfd5e6eb3f0bbf180099fc05): fix detecting duplicated namespaces problem
- [75d5d40](https://github.com/quay/clair/commit/75d5d40d796f4233a58c16443614933c8b326d49): added multiple namespace testing for namespace detector
### Fix
- [4e49aaf](https://github.com/quay/clair/commit/4e49aaf34647ab636595c1ba631efa0cea56ceac): lock updater - return correct bool value
### Github
- [6a42aba](https://github.com/quay/clair/commit/6a42aba3aa7c73627fd73da3d57dd233de1184e8): add mailing list!
- [c7a67ed](https://github.com/quay/clair/commit/c7a67edf5d8957ff05391770d6800e9e83b6b0a9): add issue template stable release notice
- [f6cac47](https://github.com/quay/clair/commit/f6cac4733a7545736d5875f0b36324481098d471): add issue template
- [24ca12b](https://github.com/quay/clair/commit/24ca12bdecfcbc2d7797a01dcde87fea44dad7c8): move CONTRIBUTING to github dir
### Gitutil
- [11b67e6](https://github.com/quay/clair/commit/11b67e612c3703af63a4c63364ea60445077a2a7): Fix git pull on non-git repository directory
 - Fixes [#641](https://github.com/quay/clair/issues/641)### Glide
- [165c397](https://github.com/quay/clair/commit/165c397f169409dfce9b41459d5845e774c8ef81): add errgroup and regenerate vendor
### Go.Mod
- [28957dc](https://github.com/quay/clair/commit/28957dce0b23c2018bb3a874a4e45651173f7260): update claircore version
- [badcac4](https://github.com/quay/clair/commit/badcac4420b44d92d1d56d5f9c9a09daf8a5db50): update yaml to v3
- [ef5fbc4](https://github.com/quay/clair/commit/ef5fbc4d6dcf877a05a5a12b6dd2a7a7c50568cf): bump claircore version for severity fix
- [ad58dd9](https://github.com/quay/clair/commit/ad58dd9758726e488b5c60a47b602f1492de7204): update to latest claircore
### HELM
- [81430ff](https://github.com/quay/clair/commit/81430ffbb252990ebfd74b0bba284c7564b69dae): also add option for nodeSelector
- [6a94d8c](https://github.com/quay/clair/commit/6a94d8ccd267cc428dd2161bb1e5b71dd3cd244f): add option for tolerations
### Helm
- [690d26e](https://github.com/quay/clair/commit/690d26edbac2605b19900549b70d74fa47bdfef9): change postgresql connection string format in configmap template
 - Fixes [#561](https://github.com/quay/clair/issues/561)- [7a06a7a](https://github.com/quay/clair/commit/7a06a7a2b4a68c2567a5bcc41c497fdb9d8d2c15): Fixed a typo in maintainers field.
### Helm
- [710c655](https://github.com/quay/clair/commit/710c65530f4524693e6a863075b4d3760901a3bc): allow for ingress path configuration in values.yml
### Helm Chart
- [bc6f37f](https://github.com/quay/clair/commit/bc6f37f1ae0df5a7c01184ef1483a889e82e86ba): Use Secret for config file. Fix some minor issues
 - Fixes [#581](https://github.com/quay/clair/issues/581)### Httptransport
- [e1144aa](https://github.com/quay/clair/commit/e1144aaf0af143d63c59d1cfcc8f06490377c1d8): made discovery endpoint more Accepting
- [fb03692](https://github.com/quay/clair/commit/fb03692ecbacd9b4ada902d9fe4b2e211fced82e): add integration tests
- [54c6a6d](https://github.com/quay/clair/commit/54c6a6d46e6087690287c4b247668e954d6913af): document exposed API
- [5683018](https://github.com/quay/clair/commit/5683018f2e7d091897a238aa82e88da56941fee8): serve OpenAPI definition
- [e783062](https://github.com/quay/clair/commit/e783062b41af06eed250d289a2dfa43a4b6aeb25): wire in update endpoints
- [9cd6cab](https://github.com/quay/clair/commit/9cd6cabf62b60bd47bd2f6546cd5a806f1d79ad3): report write errors via trailer
### Imagefmt
- [891ce16](https://github.com/quay/clair/commit/891ce1697d0e53e253001d0ae7620f31b886618c): Move layer blob download logic to blob.go
### Indexer
- [500355b](https://github.com/quay/clair/commit/500355b53c213193147e653b147afc3036ea2125): add basic latency summary
- [8953724](https://github.com/quay/clair/commit/8953724bab392fa3897c2fae62b5df6e9567047c): QoL changes to headers
- [741fc2c](https://github.com/quay/clair/commit/741fc2c4bacb7e5651b05b298257a41ec7558858): HTTP correctness changes
- [10d2f54](https://github.com/quay/clair/commit/10d2f5472efc414846b56edf9d77a69246ea06b2): rename index endpoint
- [ac0a0d4](https://github.com/quay/clair/commit/ac0a0d49424f1f19b5044ea84a245e3139b5adb3): add Accept-Encoding aware middleware
- [3a9ca8e](https://github.com/quay/clair/commit/3a9ca8e57a041bdd78d5e37a904a1ff5942befd8): add State method
### Initialize
- [98c8ffd](https://github.com/quay/clair/commit/98c8ffd67dee0f5768b4fa28c86f89f114b2af7c): wire through new configuration options
### Layer
- [015a79f](https://github.com/quay/clair/commit/015a79fd5a077a3e8340f8cef8610512f53ef053): replace arrays with slices
### Local-Dev
- [d1b6012](https://github.com/quay/clair/commit/d1b6012093025413e1f3774acd895b679c21c6fc): implement quay local development
### Logging
- [15f3755](https://github.com/quay/clair/commit/15f3755b349064a9093fa199e2a89e89038a1b61): use duration stringer
- [10b8757](https://github.com/quay/clair/commit/10b87578aa55ecaed27d36964b1de18e7eaffe42): add similar logging to v3
### Mapping
- [07a08a4](https://github.com/quay/clair/commit/07a08a4f53cab155814eadde44a847e2389b5bcc): add ubuntu mapping
 - Fixes [#552](https://github.com/quay/clair/issues/552)### Matcher
- [15c098c](https://github.com/quay/clair/commit/15c098c48cac6e87b82a4af4b5914aef0ab83310): add basic latency summary
- [0017946](https://github.com/quay/clair/commit/0017946470397c252b1934d1637fe7b1d01fe280): return OK instead of Created
### Misc
- [18e4db2](https://github.com/quay/clair/commit/18e4db2c0298696797975911ff4c7b48f41b54fc): doc and commit check fixes
### Notifier
- [7d95067](https://github.com/quay/clair/commit/7d95067f4762ec1aa79879e23c7956eaef8ca4f7): remove first update constraint
- [9bd4f4d](https://github.com/quay/clair/commit/9bd4f4dfb1a5acccf6295a03fe71b51d8259b16f): test mode implementation
- [4b35c88](https://github.com/quay/clair/commit/4b35c88740c93689dd7270079f962a79cc77d27f): log better
- [717f8a0](https://github.com/quay/clair/commit/717f8a0dea82aa7e8c8f1c06de5468b06498dd0b): correctly close channels after amqp delivery
### Nvd
- [e953a25](https://github.com/quay/clair/commit/e953a259b008042d733a4c0aadc9b85d1bedf251): fix the name of a field
### Openapi
- [1949ec3](https://github.com/quay/clair/commit/1949ec3a22a5d2dd5cc30a5fccb99c49a657677a): lint and update Layer
### PgSQL
- [57a4f97](https://github.com/quay/clair/commit/57a4f977803e5eb0d5ddb23e6d54e8490efe89c9): fixed invalidating vulnerability cache query.
### Pgsql
- [0731df9](https://github.com/quay/clair/commit/0731df972c5270d2540411cc2ae1b4f3c9b36dc6): Remove unused test code
- [dfa07f6](https://github.com/quay/clair/commit/dfa07f6d860c59ba2b2cc4909d38f650e9d3969b): Move notification to its module
- [921acb2](https://github.com/quay/clair/commit/921acb26fe875ed18c95b2f62a73fa3e1a8aa355): Split vulnerability.go to files in vulnerability module
- [7cc83cc](https://github.com/quay/clair/commit/7cc83ccbc5b4e34762d10343c2bc989a14fddebc): Split ancestry.go to files in ancestry module
- [497b79a](https://github.com/quay/clair/commit/497b79a293ce9d07f34ffd8ea51264c8ae6bd84c): Add test for migrations
- [ea418cf](https://github.com/quay/clair/commit/ea418cffd474252d9a59881677daffbdaa507768): Split layer.go to files in layer module
- [176c69e](https://github.com/quay/clair/commit/176c69e59dfbd4b39d520005b712858dff502e45): Move namespace to its module
- [98e81ff](https://github.com/quay/clair/commit/98e81ff5f1230f67c3a73055f694a423763062a7): Move keyvalue to keyvalue module
- [ba50d7c](https://github.com/quay/clair/commit/ba50d7c62648471e6e7cf74afe14e9c3268a3a98): Move lock to lock module
- [0b32b36](https://github.com/quay/clair/commit/0b32b36cf7168eef2c005a3d7ec9c3a5996d910b): Move detector to pgsql/detector module
- [c50a233](https://github.com/quay/clair/commit/c50a2339b79c2b5af8552ab6ae4d0e9441df57ac): Split feature.go to table based files in feature module
- [43f3ea8](https://github.com/quay/clair/commit/43f3ea87d86097c81951faf96c000b05445d0947): Move batch queries to corresponding modules
- [a330506](https://github.com/quay/clair/commit/a33050637b4b28f947eb8256cd48ee35d2fe5bfe): Move extra logic in pgsql.go to util folder
- [8bebea3](https://github.com/quay/clair/commit/8bebea3643e294bb11a1766ec450b1e518b0003b): Split testutil.go into multiple files
- [b03f1bc](https://github.com/quay/clair/commit/b03f1bc3a671a28f914ecf012df5250ebf20df03): Fix failed tests
- [ed9c6ba](https://github.com/quay/clair/commit/ed9c6baf4faecad71828dacabc5e804a7f11252b): Fix pgsql test
- [5bf8365](https://github.com/quay/clair/commit/5bf8365f7b5bf493ec3a3c119538c58abaa29209): Prevent inserting invalid entry to database
- [8aae73f](https://github.com/quay/clair/commit/8aae73f1c8cf4dddb91babde813097789eb876f3): Remove unnecessary logs
- [79af05e](https://github.com/quay/clair/commit/79af05e67d6e6f09bd1913dbfe405ebdbd9a9c59): Fix postgres queries for feature_type
- [073c685](https://github.com/quay/clair/commit/073c685c5b085813a9ffbec20fa3c49332f7ec66): Add proper tests for database migration
- [c6c8fce](https://github.com/quay/clair/commit/c6c8fce39a5c28645b9626bc3774bd6b6aadd427): Add feature_type to initial schema
- [a57d806](https://github.com/quay/clair/commit/a57d80671793d48782f8d3777984e99d02dc1fd9): fix unchecked error
- [0c1b80b](https://github.com/quay/clair/commit/0c1b80b2ed54dcbe227f7233468a5bdc66d4a17e): Implement database queries for detector relationship
- [9c49d9d](https://github.com/quay/clair/commit/9c49d9dc5591d62a86632881af8d7a7f15fbf25e): Move queries to corresponding files
- [dca2d4e](https://github.com/quay/clair/commit/dca2d4e597ba837b6f96f3b3e32e23f6b843f9ab): Add detector to database schema
- [5343309](https://github.com/quay/clair/commit/53433090a39195d9df7c920d2e4d142f89abae31): update the query format
- [aea7455](https://github.com/quay/clair/commit/aea74550e14a0f0121fb21a2bba6bb6882c2050f): Expand layer, namespace column widths
### Pkg
- [c3904c9](https://github.com/quay/clair/commit/c3904c9696bddc20a27db9b4142ae704350bbe3f): Add fsutil to contian file system utility functions
### Pkg/Gitutil
- [c2d887f](https://github.com/quay/clair/commit/c2d887f9e99184af502aca7abbe2044d2929e789): init
### Pkg/Grpcutil
- [c4a3254](https://github.com/quay/clair/commit/c4a32543e85a46a94012cfd03fc199854ccf3b44): use cockroachdb cipher suite
- [1ec2759](https://github.com/quay/clair/commit/1ec2759550d6a6bcae7c7252c8718b783426c653): init
### Pkg/Pagination
- [0565938](https://github.com/quay/clair/commit/05659389569549f445eefac650df260ab4f4f05b): add token type
- [d193b46](https://github.com/quay/clair/commit/d193b46449a64a554c3b54dd637a371769bfe195): init
### Pkg/Timeutil
- [45ecf18](https://github.com/quay/clair/commit/45ecf1881521281f09e437c904e1f211dc36e319): init
### README
- [4db72b8](https://github.com/quay/clair/commit/4db72b8c26a5754d61931c2fd5a6ee1829b9f016): fixed issues address
- [6c3b398](https://github.com/quay/clair/commit/6c3b398607f701ac8f016c804f2b2883c0ca1db9): fix IRC copypasta
### Style
- [bd68578](https://github.com/quay/clair/commit/bd68578b8bdd4488e197ccdf6d9322380c6ae7d0): Fix typo in headline
### Tarutil
- [a3a3707](https://github.com/quay/clair/commit/a3a37072b54840aaebde1cd0bba62b8939dafbdc): convert all filename specs to regexps
- [afd7fe2](https://github.com/quay/clair/commit/afd7fe2554d65040b27291d658af21af8f8ae521): allow file names to be specified by regexp
 - fixes [#456](https://github.com/quay/clair/issues/456)### Travis
- [870e812](https://github.com/quay/clair/commit/870e8123769a3dd717bfdcd21473a8e691806653): Drop support for postgres 9.4 postgres 9.4 doesn't support ON CONFLICT, which is required in our implementation.
### Travis
- [52ecf35](https://github.com/quay/clair/commit/52ecf35ca67558c1bedefb2259e9af9ad9649f9d): fail if not gofmt -s
- [7492aa3](https://github.com/quay/clair/commit/7492aa31baf5b834088ecb8e8bd6ffd7817e5dd7): fail unformatted protos
### Update Documentation
- [1105102](https://github.com/quay/clair/commit/1105102b8449fcf20b8db1b1722eeeeece2f33fa): talk about SUSE support
### Update The Ingress To Use ApiVersion
- [435d053](https://github.com/quay/clair/commit/435d05394a9e7895d8daf2804bbe3668e1666981): networking.k8s.io/v1beta1
### Updater
- [a14b372](https://github.com/quay/clair/commit/a14b372838a72d24110b57c6443d784d6fbe4451): fix stuck updater process
### Updater
- [7084a22](https://github.com/quay/clair/commit/7084a226ae9c5a3aed1248ad3d653100d610146c): extract deduplicate function
- [e16d17d](https://github.com/quay/clair/commit/e16d17dda9d29e8fdc33ef9da6a4a8be0e6b648f): remove original RunUpdate()
- [0d41968](https://github.com/quay/clair/commit/0d41968acdeeb2325bf9573a65fd1d05345ba255): reimplement fetch() with errgroup
- [6c5be7e](https://github.com/quay/clair/commit/6c5be7e1c6856fbae55e77c0a3411e7fe4d61f82): refactor to use errgroup
- [2236b0a](https://github.com/quay/clair/commit/2236b0a5c9a094bde2b7979417b9538cb944e726): Add vulnsrc affected feature type
- [0d18a62](https://github.com/quay/clair/commit/0d18a629cab15d57fb7b00777f1537039b69401b): sleep before continuing the lock loop
 - Fixes [#415](https://github.com/quay/clair/issues/415)### Updater,Pkg/Timeutil
- [f64bd11](https://github.com/quay/clair/commit/f64bd117b2fa946c26a2e3368925f6dae8e4a2d3): minor cleanups
### Upgrade To Golang
- [db5dbbe](https://github.com/quay/clair/commit/db5dbbe4e983a4ac827f5b6597aac780c03124b3): 1.10-alpine
### V3
- [88f5069](https://github.com/quay/clair/commit/88f506918b9cb32ab77e41e0cbbe2f9db6e6b358): Analyze layer content in parallel
- [dd23976](https://github.com/quay/clair/commit/dd239762f63702c1800895ee9b86bdda316830ef): Move services to top of the file
- [9f5d1ea](https://github.com/quay/clair/commit/9f5d1ea4e16793ebd9390673aed34855671b5c24): associate feature and namespace with detector
### Vendor
- [4106322](https://github.com/quay/clair/commit/41063221075cea67636f77f58a9d3e112771b835): Update gopkg.in/yaml.v2 package
- [34d0e51](https://github.com/quay/clair/commit/34d0e516e0792ca2d06299a1262e5676d4145f80): Add golang-set dependency
- [55ecf1e](https://github.com/quay/clair/commit/55ecf1e58aa75346ca6c4d702eb31e02ff32ee0e): regenerate after removing graceful
- [1533dd1](https://github.com/quay/clair/commit/1533dd1d51d4f89febd857897addb6dfb6c161e4): updated vendor dir for grpc v2 api
### Vulnmdsrc
- [ce6b008](https://github.com/quay/clair/commit/ce6b00887b1db3a402b1a02bdebb5bcc23d4add0): update NVD URLs
 - Fixes [#575](https://github.com/quay/clair/issues/575)### Vulnsrc
- [72674ca](https://github.com/quay/clair/commit/72674ca871dd2b0a9afdbd9c6a6b50f49a50b20b): Refactor vulnerability sources to use utility functions
### Vulnsrc Rhel
- [bd7102d](https://github.com/quay/clair/commit/bd7102d96304b02ff09077edc16f5f60bd784c8b): handle "none" CVE impact
### Vulnsrc/Alpine
- [c031f8e](https://github.com/quay/clair/commit/c031f8ea0c793ba0462f2b8a204c15ab3a65f1a5): s/pull/clone
- [4c2be52](https://github.com/quay/clair/commit/4c2be5285e1419844377c11484bd684b45948958): avoid shadowing vars
### Vulnsrc/Ubuntu
- [456af5f](https://github.com/quay/clair/commit/456af5f48c8da8325266209e58cec90f4a3f1f68): use new git-based ubuntu tracker
### Vulnsrc_oracle
- [3503ddb](https://github.com/quay/clair/commit/3503ddb96fe412242b84ec28f36a7ddd787b823f): one vulnerability per CVE
 -  [#495](https://github.com/quay/clair/issues/495) -  [#499](https://github.com/quay/clair/issues/499)### Vulnsrc_rhel
- [c4ffa0c](https://github.com/quay/clair/commit/c4ffa0c370e793546dd51ea25fc98961c2d25970): cve impact
- [a90db71](https://github.com/quay/clair/commit/a90db713a2722a80db33e47343c4a4d417f48a0e): add test
- [8b3338e](https://github.com/quay/clair/commit/8b3338ef56b060e27bc3d81124f52bbded315f1a): minor changes
- [4e4e98f](https://github.com/quay/clair/commit/4e4e98f328309d1c0a470388d198fa37c27e47d5): minor changes
- [ac86a36](https://github.com/quay/clair/commit/ac86a3674094f93b71e8736392b7a4707fa972fe): rhsa_ID by default
- [4ab98cf](https://github.com/quay/clair/commit/4ab98cfe54bedcce7880cc03b1c52d5a91811860): one vulnerability by CVE
 - Fixes [#495](https://github.com/quay/clair/issues/495)### Worker
- [23ccd9b](https://github.com/quay/clair/commit/23ccd9b53ba0a8bcf800fecdbd72d5cbefd2ea60): Fix tests for feature_type
- [f0e21df](https://github.com/quay/clair/commit/f0e21df7830e3f8d00498936d0d292ae6ff6765b): fixed duplicated ns and ns not inherited bug
### Workflows
- [f003924](https://github.com/quay/clair/commit/f0039247e1f4c8a2f97b81896782cb802cdeffd8): add go testing matrix
- [ea5873b](https://github.com/quay/clair/commit/ea5873bc8f57eb4d545e0a25a2da868371196926): fix gh-pages argument
- [cec05a3](https://github.com/quay/clair/commit/cec05a35f71dffb6603a2debb14d5388e80643c7): more workflow automation
- [a19407e](https://github.com/quay/clair/commit/a19407e4fd40585b45ffceb507e24c194db78ccc): fix asset name
- [e1902d4](https://github.com/quay/clair/commit/e1902d4d7c1f7d7fdccc6b339736966d2ece0cf6): proper tag name
- [b2d781c](https://github.com/quay/clair/commit/b2d781c2ed50262f4882e34b2585bf99d80fb15b): bad tar flag
### Pull Requests
- Merge pull request [#955](https://github.com/quay/clair/issues/955) from alecmerdler/openapi-fixes
- Merge pull request [#949](https://github.com/quay/clair/issues/949) from alecmerdler/PROJQUAY-494
- Merge pull request [#936](https://github.com/quay/clair/issues/936) from ldelossa/louis/interface-refactor
- Merge pull request [#933](https://github.com/quay/clair/issues/933) from ldelossa/louis/config-and-make
- Merge pull request [#930](https://github.com/quay/clair/issues/930) from ldelossa/louis/middleware-packaging
- Merge pull request [#929](https://github.com/quay/clair/issues/929) from ldelossa/louis/cc-bump-v0.0.17
- Merge pull request [#924](https://github.com/quay/clair/issues/924) from ldelossa/louis/severity-mapping
- Merge pull request [#903](https://github.com/quay/clair/issues/903) from ldelossa/louis/environment-api
- Merge pull request [#897](https://github.com/quay/clair/issues/897) from ldelossa/louis/state-json
- Merge pull request [#890](https://github.com/quay/clair/issues/890) from ldelossa/louis/remove-healthhandler
- Merge pull request [#877](https://github.com/quay/clair/issues/877) from mtougeron/update-ingress-apiversion
- Merge pull request [#873](https://github.com/quay/clair/issues/873) from coreos/code-owners-update
- Merge pull request [#867](https://github.com/quay/clair/issues/867) from andrewsharon/ubuntu19.10
- Merge pull request [#861](https://github.com/quay/clair/issues/861) from thekbb/fix-broken-link-i-missed
- Merge pull request [#856](https://github.com/quay/clair/issues/856) from thekbb/fix-links
- Merge pull request [#860](https://github.com/quay/clair/issues/860) from jzelinskie/bump-v2-master
- Merge pull request [#851](https://github.com/quay/clair/issues/851) from Allda/log-fix
- Merge pull request [#774](https://github.com/quay/clair/issues/774) from Allda/updater_fix
- Merge pull request [#839](https://github.com/quay/clair/issues/839) from noahklein/nvd-status-error
- Merge pull request [#829](https://github.com/quay/clair/issues/829) from peacocb/peacocb-828-dos-on-ancestry-post
- Merge pull request [#831](https://github.com/quay/clair/issues/831) from MVrachev/patch-1
- Merge pull request [#818](https://github.com/quay/clair/issues/818) from vsamidurai/master
- Merge pull request [#822](https://github.com/quay/clair/issues/822) from imlonghao/bullseye
- Merge pull request [#817](https://github.com/quay/clair/issues/817) from ldelossa/remove-detectors
- Merge pull request [#755](https://github.com/quay/clair/issues/755) from Allda/openshift_cert
- Merge pull request [#808](https://github.com/quay/clair/issues/808) from coreos/add-louis
- Merge pull request [#797](https://github.com/quay/clair/issues/797) from jzelinskie/drone
- Merge pull request [#805](https://github.com/quay/clair/issues/805) from ldelossa/remove-ancestry-copy
- Merge pull request [#794](https://github.com/quay/clair/issues/794) from ldelossa/local-dev-readme-update
- Merge pull request [#793](https://github.com/quay/clair/issues/793) from ldelossa/local-dev-clair-db
- Merge pull request [#788](https://github.com/quay/clair/issues/788) from ldelossa/helm-local-dev
- Merge pull request [#780](https://github.com/quay/clair/issues/780) from jzelinskie/CODEOWNERS
- Merge pull request [#779](https://github.com/quay/clair/issues/779) from jzelinskie/mailing-list
- Merge pull request [#773](https://github.com/quay/clair/issues/773) from flumm/disco
- Merge pull request [#671](https://github.com/quay/clair/issues/671) from ericysim/amazon
- Merge pull request [#766](https://github.com/quay/clair/issues/766) from Allda/lock_timeout
- Merge pull request [#742](https://github.com/quay/clair/issues/742) from bluelabsio/path-templating
- Merge pull request [#739](https://github.com/quay/clair/issues/739) from joelee2012/master
- Merge pull request [#749](https://github.com/quay/clair/issues/749) from cnorthwood/tarutil-glob
- Merge pull request [#741](https://github.com/quay/clair/issues/741) from KeyboardNerd/parallel_download
- Merge pull request [#738](https://github.com/quay/clair/issues/738) from Allda/potentialNamespaceAncestry
- Merge pull request [#721](https://github.com/quay/clair/issues/721) from KeyboardNerd/cache
- Merge pull request [#735](https://github.com/quay/clair/issues/735) from jzelinskie/fix-sweet32
- Merge pull request [#722](https://github.com/quay/clair/issues/722) from Allda/feature_ns
- Merge pull request [#724](https://github.com/quay/clair/issues/724) from KeyboardNerd/ref
- Merge pull request [#728](https://github.com/quay/clair/issues/728) from KeyboardNerd/fix
- Merge pull request [#727](https://github.com/quay/clair/issues/727) from KeyboardNerd/master
- Merge pull request [#725](https://github.com/quay/clair/issues/725) from KeyboardNerd/license_test
- Merge pull request [#723](https://github.com/quay/clair/issues/723) from jzelinskie/lock-tx
- Merge pull request [#720](https://github.com/quay/clair/issues/720) from KeyboardNerd/update_ns
- Merge pull request [#695](https://github.com/quay/clair/issues/695) from saromanov/fix-unchecked-error
- Merge pull request [#712](https://github.com/quay/clair/issues/712) from KeyboardNerd/builder
- Merge pull request [#672](https://github.com/quay/clair/issues/672) from KeyboardNerd/source_package/feature_type
- Merge pull request [#685](https://github.com/quay/clair/issues/685) from jzelinskie/updater-cleanup
- Merge pull request [#701](https://github.com/quay/clair/issues/701) from dustinspecker/patch-1
- Merge pull request [#700](https://github.com/quay/clair/issues/700) from traum-ferienwohnungen/master
- Merge pull request [#680](https://github.com/quay/clair/issues/680) from Allda/slices
- Merge pull request [#687](https://github.com/quay/clair/issues/687) from jzelinskie/suse-config
- Merge pull request [#686](https://github.com/quay/clair/issues/686) from jzelinskie/fix-presentations
- Merge pull request [#679](https://github.com/quay/clair/issues/679) from kubeshield/master
- Merge pull request [#506](https://github.com/quay/clair/issues/506) from openSUSE/reintroduce-suse-opensuse
- Merge pull request [#681](https://github.com/quay/clair/issues/681) from Allda/rhel_severity
- Merge pull request [#667](https://github.com/quay/clair/issues/667) from travelaudience/helm-tolerations
- Merge pull request [#656](https://github.com/quay/clair/issues/656) from glb/elsa_CVEID
- Merge pull request [#650](https://github.com/quay/clair/issues/650) from Katee/add-ubuntu-cosmic
- Merge pull request [#653](https://github.com/quay/clair/issues/653) from brosander/helm-dep
- Merge pull request [#648](https://github.com/quay/clair/issues/648) from HaraldNordgren/go_versions
- Merge pull request [#647](https://github.com/quay/clair/issues/647) from KeyboardNerd/spkg/cvrf
- Merge pull request [#644](https://github.com/quay/clair/issues/644) from KeyboardNerd/bug/git
- Merge pull request [#645](https://github.com/quay/clair/issues/645) from Katee/include-cvssv3
- Merge pull request [#646](https://github.com/quay/clair/issues/646) from KeyboardNerd/spkg/model
- Merge pull request [#640](https://github.com/quay/clair/issues/640) from KeyboardNerd/sourcePackage
- Merge pull request [#639](https://github.com/quay/clair/issues/639) from Katee/update-sha1-to-sha256
- Merge pull request [#638](https://github.com/quay/clair/issues/638) from KeyboardNerd/featureTree
- Merge pull request [#633](https://github.com/quay/clair/issues/633) from coreos/roadmap-1
- Merge pull request [#620](https://github.com/quay/clair/issues/620) from KeyboardNerd/feature/detector
- Merge pull request [#627](https://github.com/quay/clair/issues/627) from haydenhughes/master
- Merge pull request [#624](https://github.com/quay/clair/issues/624) from jzelinskie/probot
- Merge pull request [#621](https://github.com/quay/clair/issues/621) from jzelinskie/gitutil
- Merge pull request [#610](https://github.com/quay/clair/issues/610) from MackJM/wip/master_nvd_httputil
- Merge pull request [#499](https://github.com/quay/clair/issues/499) from yebinama/rhel_CVEID
- Merge pull request [#619](https://github.com/quay/clair/issues/619) from KeyboardNerd/sidac/rm_layer
- Merge pull request [#617](https://github.com/quay/clair/issues/617) from jzelinskie/grpc-refactor
- Merge pull request [#614](https://github.com/quay/clair/issues/614) from KeyboardNerd/sidac/simplify
- Merge pull request [#613](https://github.com/quay/clair/issues/613) from jzelinskie/pkg-pagination
- Merge pull request [#611](https://github.com/quay/clair/issues/611) from jzelinskie/drop-graceful
- Merge pull request [#605](https://github.com/quay/clair/issues/605) from KeyboardNerd/sidchen/feature
- Merge pull request [#606](https://github.com/quay/clair/issues/606) from MackJM/wip/master_httputil
- Merge pull request [#607](https://github.com/quay/clair/issues/607) from jzelinskie/gofmt
- Merge pull request [#604](https://github.com/quay/clair/issues/604) from jzelinskie/nvd-urls
- Merge pull request [#601](https://github.com/quay/clair/issues/601) from KeyboardNerd/sidchen/status
- Merge pull request [#594](https://github.com/quay/clair/issues/594) from reasonerjt/fix-alpine-url
- Merge pull request [#578](https://github.com/quay/clair/issues/578) from naibaf0/fix/helmtemplate/configmap/postgresql
- Merge pull request [#586](https://github.com/quay/clair/issues/586) from robertomlsoares/update-helm-chart
- Merge pull request [#582](https://github.com/quay/clair/issues/582) from brosander/helm-alpine-postgres
- Merge pull request [#571](https://github.com/quay/clair/issues/571) from ErikThoreson/nvdupdates
- Merge pull request [#574](https://github.com/quay/clair/issues/574) from hongli-my/fix-nvd-path
- Merge pull request [#572](https://github.com/quay/clair/issues/572) from arno01/multi-stage
- Merge pull request [#540](https://github.com/quay/clair/issues/540) from jzelinskie/document-proto
- Merge pull request [#569](https://github.com/quay/clair/issues/569) from jzelinskie/ubuntu-git
- Merge pull request [#553](https://github.com/quay/clair/issues/553) from qeqar/master
- Merge pull request [#551](https://github.com/quay/clair/issues/551) from usr42/upgrade_to_1.10-alpine
- Merge pull request [#538](https://github.com/quay/clair/issues/538) from jzelinskie/dockerize-protogen
- Merge pull request [#537](https://github.com/quay/clair/issues/537) from tomer-1/patch-1
- Merge pull request [#532](https://github.com/quay/clair/issues/532) from KeyboardNerd/readme_typo
- Merge pull request [#508](https://github.com/quay/clair/issues/508) from joerayme/bug/436
- Merge pull request [#528](https://github.com/quay/clair/issues/528) from KeyboardNerd/helm_typo
- Merge pull request [#522](https://github.com/quay/clair/issues/522) from vdboor/master
- Merge pull request [#521](https://github.com/quay/clair/issues/521) from yebinama/paclair
- Merge pull request [#518](https://github.com/quay/clair/issues/518) from traum-ferienwohnungen/master
- Merge pull request [#513](https://github.com/quay/clair/issues/513) from leandrocr/patch-1
- Merge pull request [#517](https://github.com/quay/clair/issues/517) from KeyboardNerd/master
- Merge pull request [#505](https://github.com/quay/clair/issues/505) from ericchiang/coc
- Merge pull request [#484](https://github.com/quay/clair/issues/484) from odg0318/master
- Merge pull request [#498](https://github.com/quay/clair/issues/498) from bkochendorfer/contributing-link
- Merge pull request [#482](https://github.com/quay/clair/issues/482) from yfoelling/patch-1
- Merge pull request [#487](https://github.com/quay/clair/issues/487) from ajgreenb/db-connection-backoff
- Merge pull request [#488](https://github.com/quay/clair/issues/488) from caulagi/patch-1
- Merge pull request [#485](https://github.com/quay/clair/issues/485) from yebinama/proxy
- Merge pull request [#481](https://github.com/quay/clair/issues/481) from coreos/stable-release-issue-template
- Merge pull request [#479](https://github.com/quay/clair/issues/479) from yebinama/nvd_vectors
- Merge pull request [#477](https://github.com/quay/clair/issues/477) from bseb/master
- Merge pull request [#469](https://github.com/quay/clair/issues/469) from zamarrowski/master
- Merge pull request [#475](https://github.com/quay/clair/issues/475) from dctrud/clair-singularity
- Merge pull request [#467](https://github.com/quay/clair/issues/467) from grebois/master
- Merge pull request [#465](https://github.com/quay/clair/issues/465) from jzelinskie/github
- Merge pull request [#463](https://github.com/quay/clair/issues/463) from brunomcustodio/fix-ingress
- Merge pull request [#459](https://github.com/quay/clair/issues/459) from arthurlm44/patch-1
- Merge pull request [#458](https://github.com/quay/clair/issues/458) from jzelinskie/linux-vulns
- Merge pull request [#450](https://github.com/quay/clair/issues/450) from jzelinskie/move-token
- Merge pull request [#454](https://github.com/quay/clair/issues/454) from InTheCloudDan/helm-tls-option
- Merge pull request [#455](https://github.com/quay/clair/issues/455) from zmarouf/master
- Merge pull request [#449](https://github.com/quay/clair/issues/449) from jzelinskie/helm
- Merge pull request [#447](https://github.com/quay/clair/issues/447) from KeyboardNerd/ancestry_
- Merge pull request [#448](https://github.com/quay/clair/issues/448) from jzelinskie/woops
- Merge pull request [#444](https://github.com/quay/clair/issues/444) from jzelinskie/docs-refresh
- Merge pull request [#432](https://github.com/quay/clair/issues/432) from KeyboardNerd/ancestry_
- Merge pull request [#442](https://github.com/quay/clair/issues/442) from arminc/add-integration-clari-scanner
- Merge pull request [#433](https://github.com/quay/clair/issues/433) from mssola/portus-integration
- Merge pull request [#408](https://github.com/quay/clair/issues/408) from KeyboardNerd/grpc
- Merge pull request [#423](https://github.com/quay/clair/issues/423) from jzelinskie/sleep-updater
- Merge pull request [#418](https://github.com/quay/clair/issues/418) from KeyboardNerd/multiplens
- Merge pull request [#410](https://github.com/quay/clair/issues/410) from KeyboardNerd/xforward
- Merge pull request [#416](https://github.com/quay/clair/issues/416) from tianon/debian-buster
- Merge pull request [#413](https://github.com/quay/clair/issues/413) from transcedentalia/master
- Merge pull request [#403](https://github.com/quay/clair/issues/403) from KeyboardNerd/multiplens
- Merge pull request [#407](https://github.com/quay/clair/issues/407) from swestcott/kubernetes-config-fix
- Merge pull request [#394](https://github.com/quay/clair/issues/394) from KeyboardNerd/multiplens
- Merge pull request [#382](https://github.com/quay/clair/issues/382) from caipre/patch-1


<a name="v2.1.5"></a>
## [v2.1.5] - 2020-09-28
### Api
- [546fd93](https://github.com/quay/clair/commit/546fd936739d6875b818a9e5ab9b84b3e860794c): use cockroachdb cipher suite
### Api/V1
- [d8560e2](https://github.com/quay/clair/commit/d8560e24c6b111857eadc6b16beb7c52bf9715ec): remove debug statement
### Clair
- [0ef7cee](https://github.com/quay/clair/commit/0ef7cee405354032fd3b22d83663ce5fe70d5e28): remove vendor directory
- [8483a69](https://github.com/quay/clair/commit/8483a696f6dba0add8443d0cbfcd305bdef2c20d): rewrite imports
- [7bc8980](https://github.com/quay/clair/commit/7bc8980e0f1bc6b5ec63ae5230c956fac12eed9e): create module
### Database
- [9a45205](https://github.com/quay/clair/commit/9a452050c85acaa573403edffff1c13921cd460a): add ubuntu cosmic mapping
- [f882e1c](https://github.com/quay/clair/commit/f882e1c2109383fd8a46c33b86c8960d84b5fc90): add ubuntu bionic namespace mapping
### Dockerfile
- [5fed354](https://github.com/quay/clair/commit/5fed3540412d183237400af564f9774e75f4d8b8): bump to Go 1.13
### Ext/Featurens
- [8aeb337](https://github.com/quay/clair/commit/8aeb3374717e643eb7e81f95f0fda61de7042e4d): add support for RHEL8
 - Fixes [#889](https://github.com/quay/clair/issues/889)### Ext/Vulnsrc/Rhel
- [ee4380f](https://github.com/quay/clair/commit/ee4380f51a92b6ec5c29e62829c7d202cb7c3c30): s/Warning/Warningf
### Ext/Vulnsrc/Ubuntu
- [d1cadb4](https://github.com/quay/clair/commit/d1cadb4cdc4784790338aa25e755c79404966791): updated tracker src
 - Fixes [#524](https://github.com/quay/clair/issues/524)### Feat
- [d82e9b0](https://github.com/quay/clair/commit/d82e9b0e20345e29178bd277a1305037af870d02): support ubuntu 20.04 ([#987](https://github.com/quay/clair/issues/987))
 -  [#987](https://github.com/quay/clair/issues/987)- [ad6be9c](https://github.com/quay/clair/commit/ad6be9ce0191e70af9672d5aa4b69217c5606082): backport ubuntu 19.10 ([#977](https://github.com/quay/clair/issues/977))
 -  [#977](https://github.com/quay/clair/issues/977)### Featurens
- [e650d58](https://github.com/quay/clair/commit/e650d58583aa48a03f5e9f0ce2621be54cfcee40): Ensure RHEL is correctly identified
 - Fixes [#436](https://github.com/quay/clair/issues/436)### Imgfmt
- [a80ca55](https://github.com/quay/clair/commit/a80ca551cf83e7c3911e68b22f9b05addb74f911): download using http proxy from env
### Rhel
- [5731f5d](https://github.com/quay/clair/commit/5731f5d23c4da2d3953d801867e67b4ef1eab5df): make as much progress as possible on updates
### Use Golang
- [ad98b97](https://github.com/quay/clair/commit/ad98b97a6de6dd4f7cf22c419db316e8676b1bf7): 1.10-alpine with v2.0.2
### Vulnmdsrc
- [5e4c36a](https://github.com/quay/clair/commit/5e4c36aad537b4a14b96214074f97b293261bba7): update NVD URLs
 - Fixes [#575](https://github.com/quay/clair/issues/575)### Pull Requests
- Merge pull request [#898](https://github.com/quay/clair/issues/898) from rpnguyen/ubi8-backport-release-2.0
- Merge pull request [#895](https://github.com/quay/clair/issues/895) from andrewsharon/release-2.0
- Merge pull request [#887](https://github.com/quay/clair/issues/887) from ldelossa/louis/rhel-import-fix
- Merge pull request [#875](https://github.com/quay/clair/issues/875) from quay/v2-module
- Merge pull request [#876](https://github.com/quay/clair/issues/876) from reasonerjt/nvd-json-2.0
- Merge pull request [#859](https://github.com/quay/clair/issues/859) from jzelinskie/v2-bump-go
- Merge pull request [#846](https://github.com/quay/clair/issues/846) from ErikThoreson/v2.0.9-nvdfix
- Merge pull request [#840](https://github.com/quay/clair/issues/840) from glb/bugfix-231-release-2.0
- Merge pull request [#823](https://github.com/quay/clair/issues/823) from imlonghao/release-2.0-bullseye
- Merge pull request [#769](https://github.com/quay/clair/issues/769) from roxspring/backport/[gh-630](https://github.com/quay/clair/issues/630)-dumb-init
- Merge pull request [#776](https://github.com/quay/clair/issues/776) from flumm/release-2.0-disco
- Merge pull request [#736](https://github.com/quay/clair/issues/736) from jzelinskie/fix-sweet32-v2
- Merge pull request [#615](https://github.com/quay/clair/issues/615) from reasonerjt/updater-loop-2.0
- Merge pull request [#603](https://github.com/quay/clair/issues/603) from MackJM/httpclient
- Merge pull request [#599](https://github.com/quay/clair/issues/599) from reasonerjt/fix-alpine-url-2.0
- Merge pull request [#530](https://github.com/quay/clair/issues/530) from meringu/patch-1
- Merge pull request [#568](https://github.com/quay/clair/issues/568) from MackJM/release-2.0
- Merge pull request [#562](https://github.com/quay/clair/issues/562) from ninjaMog/ubuntu-tracker-update
- Merge pull request [#565](https://github.com/quay/clair/issues/565) from ninjaMog/nvd-endpoint-update
- Merge pull request [#554](https://github.com/quay/clair/issues/554) from usr42/release-2.0_go1.10
- Merge pull request [#531](https://github.com/quay/clair/issues/531) from bison/oracle-regex
- Merge pull request [#423](https://github.com/quay/clair/issues/423) from jzelinskie/sleep-updater
- Merge pull request [#407](https://github.com/quay/clair/issues/407) from swestcott/kubernetes-config-fix
- Merge pull request [#413](https://github.com/quay/clair/issues/413) from transcedentalia/master
- Merge pull request [#416](https://github.com/quay/clair/issues/416) from tianon/debian-buster


<a name="v4.0.0-rc.3"></a>
## [v4.0.0-rc.3] - 2020-09-23
### Auth
- [f00698b](https://github.com/quay/clair/commit/f00698ba36ac1b88bb77f21ca4e9d99caf28b0b1): psk fixup
### Chore
- [a38501b](https://github.com/quay/clair/commit/a38501b3aabb92b244f51268e565c1763f62622b): claircore bump to v0.1.8
### Client
- [32b327f](https://github.com/quay/clair/commit/32b327f701f579d595b5b94cb7ca08813e366101): fix nil check
### Deployment
- [bc4c324](https://github.com/quay/clair/commit/bc4c3243c0e0bb952bb2e5d7a29d9e5d08e71962): use service prefix for simplified path routing
### Docs
- [4f35fd0](https://github.com/quay/clair/commit/4f35fd0959cbfb2f7c195c45d17d1c90ca1b7390): rework mdbook
### Logging
- [15f3755](https://github.com/quay/clair/commit/15f3755b349064a9093fa199e2a89e89038a1b61): use duration stringer
- [10b8757](https://github.com/quay/clair/commit/10b87578aa55ecaed27d36964b1de18e7eaffe42): add similar logging to v3

<a name="v4.0.0-rc.2"></a>
## [v4.0.0-rc.2] - 2020-09-11
### Chore
- [f41fba5](https://github.com/quay/clair/commit/f41fba5087f0ff5ebcd3724cb22975a5547fa572): bump cc and golang container

<a name="v4.0.0-rc.1"></a>
## [v4.0.0-rc.1] - 2020-09-10
### Auth
- [29ed5f6](https://github.com/quay/clair/commit/29ed5f60b8dfe882f95aae7d61b1e373e06a2145): use better guesses for "aud" claim
- [6932ad3](https://github.com/quay/clair/commit/6932ad3264c3b1760ef46d094b25c12664cee1cc): add keyserver algorithm allowlist
- [dc91ec9](https://github.com/quay/clair/commit/dc91ec9e96db7ab7eee853c89a768ac0414a8f9a): test multiple PSK signing algorithms
### Clairctl
- [c0a9c0b](https://github.com/quay/clair/commit/c0a9c0b7d336de1377eb3cb14fb8a1af97a49b3e): init default updaters
- [050bc2d](https://github.com/quay/clair/commit/050bc2d1f44824f2573c6219a21d3a00e1ce7a76): add import and export commands
### Config
- [03cf755](https://github.com/quay/clair/commit/03cf7555ab13856fddd5b71e1374d1f7281a800e): update matcher configurables
- [daf2e29](https://github.com/quay/clair/commit/daf2e296e9d2bc2b4d40f18ff00937829f469c04): reorganize updater configuration
### Deployment
- [0fe5f73](https://github.com/quay/clair/commit/0fe5f7315c90bc5c0e984fa6de72b96c79dec27c): ubi8 based dockerfile
 -  [#198](https://github.com/quay/clair/issues/198)### Go.Mod
- [28957dc](https://github.com/quay/clair/commit/28957dce0b23c2018bb3a874a4e45651173f7260): update claircore version
### Httptransport
- [fb03692](https://github.com/quay/clair/commit/fb03692ecbacd9b4ada902d9fe4b2e211fced82e): add integration tests
### Initialize
- [98c8ffd](https://github.com/quay/clair/commit/98c8ffd67dee0f5768b4fa28c86f89f114b2af7c): wire through new configuration options
### Local-Dev
- [d1b6012](https://github.com/quay/clair/commit/d1b6012093025413e1f3774acd895b679c21c6fc): implement quay local development
### Notifier
- [9bd4f4d](https://github.com/quay/clair/commit/9bd4f4dfb1a5acccf6295a03fe71b51d8259b16f): test mode implementation
- [4b35c88](https://github.com/quay/clair/commit/4b35c88740c93689dd7270079f962a79cc77d27f): log better
- [717f8a0](https://github.com/quay/clair/commit/717f8a0dea82aa7e8c8f1c06de5468b06498dd0b): correctly close channels after amqp delivery

<a name="v4.0.0-alpha.test"></a>
## [v4.0.0-alpha.test] - 2020-08-22
### Cidi
- [4e74f38](https://github.com/quay/clair/commit/4e74f382a20605ae2292834ff2558ffbc227a3c4): attempt changelog in release draft

<a name="v4.0.0-alpha.7"></a>
## [v4.0.0-alpha.7] - 2020-06-01
### *
- [74efdf6](https://github.com/quay/clair/commit/74efdf6b51e3e625ca9f122e7aa88e88f4708a68): update roadmap
 - Fixes [#626](https://github.com/quay/clair/issues/626)- [ce15f73](https://github.com/quay/clair/commit/ce15f73501b758b3d24e06753ce62123d0a36920): gofmt -s
- [5caa821](https://github.com/quay/clair/commit/5caa821c80a4efa2986728d6f223552b44f6ce15): remove bzr dependency
- [033cae7](https://github.com/quay/clair/commit/033cae7d358b2f7b866da7d9be3367d902cdf035): regenerate bill of materials
- [1f5bc26](https://github.com/quay/clair/commit/1f5bc26320bc58676d88c096404a8503dca7a4d8): rename example config
### .Github
- [9b1f205](https://github.com/quay/clair/commit/9b1f2058338b8aeaa5441091b4920731235f1353): add stale and issue template enforcement
### API
- [0151dba](https://github.com/quay/clair/commit/0151dbaef81cae54aa95dd8abf36d58414de2b26): change api port to api addr, rename RunV2 to Run.
 - Fixes [#446](https://github.com/quay/clair/issues/446)- [a378cb0](https://github.com/quay/clair/commit/a378cb070cb9ec56f363ec08adb8e023bfb3994e): drop v1 api, changed v2 api for Clair v3.
### All
- [fbbffcd](https://github.com/quay/clair/commit/fbbffcd2c2a34d8a6128a06a399234b444c74d09): add opentelemetry hooks
### Api
- [69c0c84](https://github.com/quay/clair/commit/69c0c84348c74749cd1d12ee4e4959991621a59d): Rename detector type to DType
- [48427e9](https://github.com/quay/clair/commit/48427e9b8808f86929ffb905952395c91644f04e): Add detectors for RPC
- [dc6be5d](https://github.com/quay/clair/commit/dc6be5d1b073d87b2405d84d33f5bb5f6ced490e): remove handleShutdown func
- [30644fc](https://github.com/quay/clair/commit/30644fcc01df7748d8e2ae15c427f01702dd4e90): remove dependency on graceful
- [58022d9](https://github.com/quay/clair/commit/58022d97e3ec7194e89522c9adb866a85c704378): renamed V2 API to V3 API for consistency.
- [c6f0eaa](https://github.com/quay/clair/commit/c6f0eaa3c82197f15371b4d2c8af686d8a7a569f): fix remote addr shows reverse proxy addr problem
- [a4edf38](https://github.com/quay/clair/commit/a4edf385663b2e412e1fd64f7d45e1ee01749798): v2 api with gRPC and gRPC-gateway
 - Fixes [#98](https://github.com/quay/clair/issues/98)### Api,Database
- [a75b8ac](https://github.com/quay/clair/commit/a75b8ac7ffe3ccd7ff9c4718e547c6c5103e9747): updated version_format documentation.
 - Fixes [#514](https://github.com/quay/clair/issues/514)### Api/V3
- [32b11e5](https://github.com/quay/clair/commit/32b11e54eb287ed0d686ba72fe413b773b748a38): Add feature type to API feature
- [f550dd1](https://github.com/quay/clair/commit/f550dd16a01edc17de0e3c658c5f7bc25639a0a1): remove dependency on google empty message
- [d7a751e](https://github.com/quay/clair/commit/d7a751e0d4298442883fde30ee37c529b2bb3719): prototool format
### Api/V3/Clairpb
- [6b9f668](https://github.com/quay/clair/commit/6b9f668ea0b657526b35008f8efd9c8f0a46df9b): document and regenerate protos
- [ec5014f](https://github.com/quay/clair/commit/ec5014f8a13605458faf1894bb905f2123ded0a7): regen protobufs
- [389b6e9](https://github.com/quay/clair/commit/389b6e992790f6e28b77ca5979c0589e43dbe40a): generate protobufs in docker
### CODEOWNERS
- [f20a72c](https://github.com/quay/clair/commit/f20a72c34ef80b4c1dee7b9984aa713f82e6c342): add Louis
- [abf6e74](https://github.com/quay/clair/commit/abf6e74790294bb765a68765afa9d8e73c3fab22): init
### Clair
- [fa95f5d](https://github.com/quay/clair/commit/fa95f5d80c86f3e916661156f99dac6fcc91a3bb): bump claircore version
- [42b1ba9](https://github.com/quay/clair/commit/42b1ba9f91f9174397280152eca5a0096342019e): use Etag header to communicate indexer state change
- [fd5993f](https://github.com/quay/clair/commit/fd5993f9765cc23355e5895105a15b71e5eb3156): add "mode" argument
- [4091329](https://github.com/quay/clair/commit/409132958e0538046e3481d3197e192316b06d91): change version information
- [8cbddd1](https://github.com/quay/clair/commit/8cbddd187e7065315417ca2f86a5e261f3d92651): better introspection server defaults
- [c097454](https://github.com/quay/clair/commit/c097454c182daa68427918d0ba2fe24bbdf6ed71): logging and introspection setup
- [a003aa4](https://github.com/quay/clair/commit/a003aa414ead82a32b24a977e301e5697718ec43): add configuration for introspection
- [d9db7c1](https://github.com/quay/clair/commit/d9db7c153ce80d3d47bbb342bd6ef873bc2954b4): use "Updaters" config option
- [48daeae](https://github.com/quay/clair/commit/48daeaeacc5a1444a07cc6ddc20b4b800d8b43be): fix header casing
- [fb28e56](https://github.com/quay/clair/commit/fb28e569da21f847c7bbc2f97807485ea007e698): remove os.Exit call on clean shutdown
- [8039e1c](https://github.com/quay/clair/commit/8039e1c95f56353e47aaa5ed66b80244ac2d2cad): add authorization checking
- [1b41336](https://github.com/quay/clair/commit/1b41336265126c23b152d18c28ea6e0fd3d6baf8): update claircore to 0.0.14
- [791610f](https://github.com/quay/clair/commit/791610f1c893fc76d6fcf350a7383a2479aa723a): remove goautoneg
- [7b6ef7d](https://github.com/quay/clair/commit/7b6ef7da8c125111ec37fe61206dce1ee25408ec): reset writers when pulled from pool
- [ad73d74](https://github.com/quay/clair/commit/ad73d747fcc6c674752eaf5ae7ccdcb6fa4daead): remove vendor directory
- [00eff59](https://github.com/quay/clair/commit/00eff59af580893d3e045333fa095d3507a528f1): rewrite imports
- [1f2ceeb](https://github.com/quay/clair/commit/1f2ceeb8f7fcf9e8ce94206f76a8b610b84424ca): create module
- [c6497dd](https://github.com/quay/clair/commit/c6497dda0a95a3309dc649761243250634a31d40): Fix namespace update logic
- [465687f](https://github.com/quay/clair/commit/465687fa94b4e9fe00e0ba1190989d0d454c14ab): Add more logging on ancestry cache hit
- [5b23764](https://github.com/quay/clair/commit/5b2376498bbc0ea0a893754887defce4daa59daa): Use builder pattern for constructing ancestry
- [0283240](https://github.com/quay/clair/commit/028324014ba3b7111e4e4533d6a8d4d99bb1fd72): Implement worker detector support
### Clair Logic, Extensions
- [fb32dcf](https://github.com/quay/clair/commit/fb32dcfa58077dadd8bfbf338c4aa342d5e9ef85): updated mock tests, extensions, basic logic
### Clairctl
- [2e68178](https://github.com/quay/clair/commit/2e6817881eed93af469abd7e16839961aa812469): remove log.Lmsgprefix
- [0282f68](https://github.com/quay/clair/commit/0282f68bf381a5b0a592079819e38b3d88296f92): report command
- [f1c4798](https://github.com/quay/clair/commit/f1c4798bb10292fe1f14d71691ab33d4ea5a2ae9): start on clair cli tool
### Client
- [1ba6891](https://github.com/quay/clair/commit/1ba68911163afb001cd89cf84862506f008edcf4): add differ and refactor client
### Cmd/Clair
- [b20482e](https://github.com/quay/clair/commit/b20482e0aebcf2cc67f61e8ff821ddcdffc53ac7): document constants
### Config
- [3ccc6e0](https://github.com/quay/clair/commit/3ccc6e03be0ce1b6c439d5c0649ee785dc7c559f): add support for per-scanner configuration
- [a93271b](https://github.com/quay/clair/commit/a93271b3be48ebe617363751d64e26840678583e): implement base64 -> []byte conversion ([#984](https://github.com/quay/clair/issues/984))
 -  [#984](https://github.com/quay/clair/issues/984)- [2ed3c2c](https://github.com/quay/clair/commit/2ed3c2c800bb9639618a86f33916625b0a595f49): rework auth config
- [b2666e5](https://github.com/quay/clair/commit/b2666e57202d7c690a40d7c86975c13e0b3db56e): set a canonical default port
- [4f23269](https://github.com/quay/clair/commit/4f232698b0178ef9d1a3cde01b6ff40e47659cfa): add updaters and tracing options
- [162e8cd](https://github.com/quay/clair/commit/162e8cdafc66be28b021f83da736a2b612ddda99): enable suse updater
- [0609ed9](https://github.com/quay/clair/commit/0609ed964b0673806462a24147e6028da85d8a38): removed worker config
### Contrib
- [76b9f8e](https://github.com/quay/clair/commit/76b9f8ea05b110d1ff659964fc9126824ec28b17): replace old k8s manifests with helm
- [ac1cdd0](https://github.com/quay/clair/commit/ac1cdd03c9e31ddaea627e076704f38a0d4719fb): move grafana and compose here
### Contrib/Helm/Clair
- [13be17a](https://github.com/quay/clair/commit/13be17a69082d30996d53d3087b7265007bae555): fix the ingress template
### Convert
- [f2ce832](https://github.com/quay/clair/commit/f2ce8325b975a15c977654d3be1084ad1e890bf3): return nil when detector is empty
### Database
- [506698a](https://github.com/quay/clair/commit/506698a4246e24bb3a72bd626d95bd47dc38beb8): add mapping for Ubuntu Eoan (19.10)
- [1ddc053](https://github.com/quay/clair/commit/1ddc0532e4be8dac02e171b986da51deaffbb636): Handle FindAncestryAndRollback datastore.Begin() error
 - Fixes [#828](https://github.com/quay/clair/issues/828)- [6617f56](https://github.com/quay/clair/commit/6617f560cc9ce90eece08aca29841827c72ca5c2): Rename affected type to feature type (for Amazon Linux updater)
- [3fafb73](https://github.com/quay/clair/commit/3fafb73c4fe0e9fbc03d1c5657b57ba0ca04c000): Split models.go into different files each contains one model
- [1b9ed99](https://github.com/quay/clair/commit/1b9ed99646e492a27e982ae34dea7c6fc7273c52): Move db logic to dbutil
- [961c7d4](https://github.com/quay/clair/commit/961c7d4680c58e3b01eedb4361a3fa57a1f9a904): add test for lock expiration
- [a4e7873](https://github.com/quay/clair/commit/a4e7873d1432b9b593f2e9dc44a02f2badea9002): make locks SOI & add Extend method
- [5fa1ac8](https://github.com/quay/clair/commit/5fa1ac89b9946f2e32ac666080b4f78ad1f9bbfa): Add StorageError type
- [f616753](https://github.com/quay/clair/commit/f61675355e7a296989e778f37257e6e416e6f208): Update feature model Remove source name/version fields Add Type field to indicate if it's binary package or source package
- [7dd989c](https://github.com/quay/clair/commit/7dd989c0f21bc5c4cb390f575dca9973829ef9ce): Rename affected Type to feature type
- [00eed77](https://github.com/quay/clair/commit/00eed77b451b8913771feef7a40067dd246d7872): Add feature_type database model
- [dd91597](https://github.com/quay/clair/commit/dd91597f19dae90e8b671d2c80004f0a28dc177c): remove FindLock from mock
- [399deab](https://github.com/quay/clair/commit/399deab1005b7c3541ad0dacb52bd7961b5167cc): remove FindLock()
- [300bb52](https://github.com/quay/clair/commit/300bb52696036dce96ee360f4431837e6ee452a2): add FindLock dbutil
- [4fbeb9c](https://github.com/quay/clair/commit/4fbeb9ced594b17aeee3e022f87ed7345376f232): add (Acquire|Release)Lock dbutils
- [6c682da](https://github.com/quay/clair/commit/6c682da3e138e0a7d09dadae7040d8cebba88e2b): add mapping for Ubuntu Cosmic (18.10)
- [a3f7387](https://github.com/quay/clair/commit/a3f7387ff146226f31a03906591cbb0d0e64cb44): Add FindKeyValue function wrapper
- [00fadfc](https://github.com/quay/clair/commit/00fadfc3e3da8c25b6c0c3f13d48017173a45a93): Add affected feature type
- [f759dd5](https://github.com/quay/clair/commit/f759dd54c028e8b39fd1e21c8c70ebda567aa7cd): Replace Parent Feature with source metadata
- [3fe894c](https://github.com/quay/clair/commit/3fe894c5ad7b33223be4a6d52bc0d88fc0fd3a18): Add parent feature pointer to Feature struct
- [a3e9b5b](https://github.com/quay/clair/commit/a3e9b5b55d13921b61e2f92a1ade9392b6e7d7a0): rename utility functions with commit/rollback
- [e657d26](https://github.com/quay/clair/commit/e657d26313b1b91fe4dab17298597119dc919cd2): move dbutil and testutil to database from pkg
- [db2db8b](https://github.com/quay/clair/commit/db2db8bbe8a17e10c9fb365196f88d552e70e91d): Update database model and interface for detectors
- [e160616](https://github.com/quay/clair/commit/e160616723643beff99363b7b385fd4b8ce6802a): Use LayerWithContent as Layer
- [ff93039](https://github.com/quay/clair/commit/ff9303905beb2e2f28d2a33e3fc232cd846b5963): changed Notification interface name
- [a5c6400](https://github.com/quay/clair/commit/a5c6400065a873f6ae14d50b73550dc07239d7bf): postgres implementation with tests.
### Database/Pgsql
- [4491bed](https://github.com/quay/clair/commit/4491bedf2e284007fa7f527bf264dc98c937d820): move token lib
### Datastore
- [57b146d](https://github.com/quay/clair/commit/57b146d0d808a29db9f299778fb5527cd0974b06): updated for Clair V3, decoupled interfaces and models
### Dockerfile
- [5a73cb4](https://github.com/quay/clair/commit/5a73cb49d64e839d7675979b5e3f348d94dd26a5): make -mod=vendor opportunisitic ([#999](https://github.com/quay/clair/issues/999))
 -  [#999](https://github.com/quay/clair/issues/999)- [33da12a](https://github.com/quay/clair/commit/33da12a3bb9a28fdbcc6302caa4212d38a2acbbb): run as unprivledged user by default
- [e56b95a](https://github.com/quay/clair/commit/e56b95aca0085067f91f90e3b32dab9d04e7fb48): use environment variables
- [33b3224](https://github.com/quay/clair/commit/33b3224df13b9c2aa8b0281f120997abce82eaf9): update for clair v4
### Dockerfile
- [2ca92d0](https://github.com/quay/clair/commit/2ca92d00754b1d1859e9d6f3169d67d6b96d6bee): bump Go to 1.13
### Dockerfile: Update To Alpine
- [de32b07](https://github.com/quay/clair/commit/de32b0728ccdbafb85988e2f87618c9d576fc87e): 3.11 for newest rpm
### Docs
- [49b5621](https://github.com/quay/clair/commit/49b5621d738978c94e8d311775bba48a1daafc7e): fix typo in running-clair
- [9ee2ff4](https://github.com/quay/clair/commit/9ee2ff4877db15a5ad8ae24afcb8f02f0e8289cf): add troubleshooting about kernel packages
- [3f91bd2](https://github.com/quay/clair/commit/3f91bd2a9bc40bd7b6f4e5a5a8a533de383f3554): turn README into full articles
### Documentation
- [fe324a5](https://github.com/quay/clair/commit/fe324a58e6be8c36da74afcd5487d0da4a547d5b): start writing v4-specific docs
- [c1a58bf](https://github.com/quay/clair/commit/c1a58bf9224bbcd7e0f02ea4065650d220654f29): add new 3rd party tool
### Documentation
- [3e6896c](https://github.com/quay/clair/commit/3e6896c6a4e5cdd04d91927d762b332b62e1d4fe): fix links to presentations
 - Closes [#661](https://github.com/quay/clair/issues/661) - Closes [#665](https://github.com/quay/clair/issues/665) - Closes [#560](https://github.com/quay/clair/issues/560)### Driver
- [5c58575](https://github.com/quay/clair/commit/5c5857548d43fa866d46a4c98309b2dfa88be418): Add proxy support
### Drone
- [0fd9cd3](https://github.com/quay/clair/commit/0fd9cd3b59bd42ef0e508f0f415028a0ee8fa44f): remove broken drone CI
- [352f738](https://github.com/quay/clair/commit/352f73834e7bdef31dc5e3a715133f5c47947764): init
### Ext
- [25078ac](https://github.com/quay/clair/commit/25078ac838920e4010ecdbe4546af0d4b502dabd): add CleanAll() utility functions
- [081ae34](https://github.com/quay/clair/commit/081ae34af146365146cf4548a8a0afa293e15695): remove duplicate vectorValuesToLetters definition
- [4f0da12](https://github.com/quay/clair/commit/4f0da12b123ec543a58936c0f7226254e411cc00): pass through CVSSv3 impact and exploitability score
- [8efc3e4](https://github.com/quay/clair/commit/8efc3e40382287e88714fdcf634a79e6347b6157): remove unneeded use of init()
- [699d114](https://github.com/quay/clair/commit/699d1143e5ab2a673d0f83249f3268cfebaf3e57): fixup incorrect copyright year
- [b81e445](https://github.com/quay/clair/commit/b81e4454fbb7f3dcec4a2dd6064820bf0c6321f2): Parse CVSSv3 data from JSON NVD feed
- [14277a8](https://github.com/quay/clair/commit/14277a8f5d95799bb651c194785dd04e75a08ee1): Add JSON NVD parsing tests
- [aab46f5](https://github.com/quay/clair/commit/aab46f5658cf5a75262945033cb41d93af5f2131): Parse NVD JSON feed instead of XML
- [8d5a013](https://github.com/quay/clair/commit/8d5a0131c48d0812d1dd53b1af8e24ae4e51c4ba): Use SHA256 instead of SHA1 for fingerprinting
- [53bf19a](https://github.com/quay/clair/commit/53bf19aecfcccb367bc359a2dd6d7320fa4e4855): Lister and Detector returns detector info with detected content
### Ext/Featurefmt
- [1c40e7d](https://github.com/quay/clair/commit/1c40e7d01697f5680408f138e6974266c6530cb1): Refactor featurefmt testing code
### Ext/Featurefmt/Apk
- [2cc61f9](https://github.com/quay/clair/commit/2cc61f9fc0edc42d2c0fda71471208e3faba507d): Extract origin package information from database
### Ext/Featurefmt/Dpkg
- [4ac0466](https://github.com/quay/clair/commit/4ac046642ffea9fb60af455b9d22d19cd4408f32): Extract source package metadata
### Ext/Featurefmt/Rpm
- [a057e4a](https://github.com/quay/clair/commit/a057e4a943dc1a2dc1898b67435b05417725402e): Extract source package from rpm database
### Feature
- [90f5592](https://github.com/quay/clair/commit/90f5592095f74e9704193f4362c494571667b326): replace arrays with slices
### Featurefmt
- [34c2d96](https://github.com/quay/clair/commit/34c2d96b3685a927749536017add6538578fb2df): Extract PotentialNamespace
- [0e0d8b3](https://github.com/quay/clair/commit/0e0d8b38bba4c62552c98ad5b98242ddd2c3464b): Extract source packages and binary packages The featurefmt now extracts both binary packages and source packages from the package manager infos.
- [9561d62](https://github.com/quay/clair/commit/9561d623c29394dddca0823721d7d3622b3dec65): use namespace's versionfmt to specify listers
### Featurens
- [947a8aa](https://github.com/quay/clair/commit/947a8aa00c6f72a20e7fca63993dafaf3185fdc4): Ensure RHEL is correctly identified
 - Fixes [#436](https://github.com/quay/clair/issues/436)- [50437f3](https://github.com/quay/clair/commit/50437f32a1d7d609cfd5e6eb3f0bbf180099fc05): fix detecting duplicated namespaces problem
- [75d5d40](https://github.com/quay/clair/commit/75d5d40d796f4233a58c16443614933c8b326d49): added multiple namespace testing for namespace detector
### Fix
- [4e49aaf](https://github.com/quay/clair/commit/4e49aaf34647ab636595c1ba631efa0cea56ceac): lock updater - return correct bool value
### Github
- [6a42aba](https://github.com/quay/clair/commit/6a42aba3aa7c73627fd73da3d57dd233de1184e8): add mailing list!
- [c7a67ed](https://github.com/quay/clair/commit/c7a67edf5d8957ff05391770d6800e9e83b6b0a9): add issue template stable release notice
- [f6cac47](https://github.com/quay/clair/commit/f6cac4733a7545736d5875f0b36324481098d471): add issue template
- [24ca12b](https://github.com/quay/clair/commit/24ca12bdecfcbc2d7797a01dcde87fea44dad7c8): move CONTRIBUTING to github dir
### Gitutil
- [11b67e6](https://github.com/quay/clair/commit/11b67e612c3703af63a4c63364ea60445077a2a7): Fix git pull on non-git repository directory
 - Fixes [#641](https://github.com/quay/clair/issues/641)### Glide
- [165c397](https://github.com/quay/clair/commit/165c397f169409dfce9b41459d5845e774c8ef81): add errgroup and regenerate vendor
### Go.Mod
- [badcac4](https://github.com/quay/clair/commit/badcac4420b44d92d1d56d5f9c9a09daf8a5db50): update yaml to v3
- [ef5fbc4](https://github.com/quay/clair/commit/ef5fbc4d6dcf877a05a5a12b6dd2a7a7c50568cf): bump claircore version for severity fix
- [ad58dd9](https://github.com/quay/clair/commit/ad58dd9758726e488b5c60a47b602f1492de7204): update to latest claircore
### HELM
- [81430ff](https://github.com/quay/clair/commit/81430ffbb252990ebfd74b0bba284c7564b69dae): also add option for nodeSelector
- [6a94d8c](https://github.com/quay/clair/commit/6a94d8ccd267cc428dd2161bb1e5b71dd3cd244f): add option for tolerations
### Helm
- [710c655](https://github.com/quay/clair/commit/710c65530f4524693e6a863075b4d3760901a3bc): allow for ingress path configuration in values.yml
### Helm
- [690d26e](https://github.com/quay/clair/commit/690d26edbac2605b19900549b70d74fa47bdfef9): change postgresql connection string format in configmap template
 - Fixes [#561](https://github.com/quay/clair/issues/561)- [7a06a7a](https://github.com/quay/clair/commit/7a06a7a2b4a68c2567a5bcc41c497fdb9d8d2c15): Fixed a typo in maintainers field.
### Helm Chart
- [bc6f37f](https://github.com/quay/clair/commit/bc6f37f1ae0df5a7c01184ef1483a889e82e86ba): Use Secret for config file. Fix some minor issues
 - Fixes [#581](https://github.com/quay/clair/issues/581)### Httptransport
- [54c6a6d](https://github.com/quay/clair/commit/54c6a6d46e6087690287c4b247668e954d6913af): document exposed API
- [5683018](https://github.com/quay/clair/commit/5683018f2e7d091897a238aa82e88da56941fee8): serve OpenAPI definition
- [e783062](https://github.com/quay/clair/commit/e783062b41af06eed250d289a2dfa43a4b6aeb25): wire in update endpoints
- [9cd6cab](https://github.com/quay/clair/commit/9cd6cabf62b60bd47bd2f6546cd5a806f1d79ad3): report write errors via trailer
### Imagefmt
- [891ce16](https://github.com/quay/clair/commit/891ce1697d0e53e253001d0ae7620f31b886618c): Move layer blob download logic to blob.go
### Indexer
- [500355b](https://github.com/quay/clair/commit/500355b53c213193147e653b147afc3036ea2125): add basic latency summary
- [8953724](https://github.com/quay/clair/commit/8953724bab392fa3897c2fae62b5df6e9567047c): QoL changes to headers
- [741fc2c](https://github.com/quay/clair/commit/741fc2c4bacb7e5651b05b298257a41ec7558858): HTTP correctness changes
- [10d2f54](https://github.com/quay/clair/commit/10d2f5472efc414846b56edf9d77a69246ea06b2): rename index endpoint
- [ac0a0d4](https://github.com/quay/clair/commit/ac0a0d49424f1f19b5044ea84a245e3139b5adb3): add Accept-Encoding aware middleware
- [3a9ca8e](https://github.com/quay/clair/commit/3a9ca8e57a041bdd78d5e37a904a1ff5942befd8): add State method
### Layer
- [015a79f](https://github.com/quay/clair/commit/015a79fd5a077a3e8340f8cef8610512f53ef053): replace arrays with slices
### Mapping
- [07a08a4](https://github.com/quay/clair/commit/07a08a4f53cab155814eadde44a847e2389b5bcc): add ubuntu mapping
 - Fixes [#552](https://github.com/quay/clair/issues/552)### Matcher
- [15c098c](https://github.com/quay/clair/commit/15c098c48cac6e87b82a4af4b5914aef0ab83310): add basic latency summary
- [0017946](https://github.com/quay/clair/commit/0017946470397c252b1934d1637fe7b1d01fe280): return OK instead of Created
### Nvd
- [e953a25](https://github.com/quay/clair/commit/e953a259b008042d733a4c0aadc9b85d1bedf251): fix the name of a field
### Openapi
- [1949ec3](https://github.com/quay/clair/commit/1949ec3a22a5d2dd5cc30a5fccb99c49a657677a): lint and update Layer
### PgSQL
- [57a4f97](https://github.com/quay/clair/commit/57a4f977803e5eb0d5ddb23e6d54e8490efe89c9): fixed invalidating vulnerability cache query.
### Pgsql
- [0731df9](https://github.com/quay/clair/commit/0731df972c5270d2540411cc2ae1b4f3c9b36dc6): Remove unused test code
- [dfa07f6](https://github.com/quay/clair/commit/dfa07f6d860c59ba2b2cc4909d38f650e9d3969b): Move notification to its module
- [921acb2](https://github.com/quay/clair/commit/921acb26fe875ed18c95b2f62a73fa3e1a8aa355): Split vulnerability.go to files in vulnerability module
- [7cc83cc](https://github.com/quay/clair/commit/7cc83ccbc5b4e34762d10343c2bc989a14fddebc): Split ancestry.go to files in ancestry module
- [497b79a](https://github.com/quay/clair/commit/497b79a293ce9d07f34ffd8ea51264c8ae6bd84c): Add test for migrations
- [ea418cf](https://github.com/quay/clair/commit/ea418cffd474252d9a59881677daffbdaa507768): Split layer.go to files in layer module
- [176c69e](https://github.com/quay/clair/commit/176c69e59dfbd4b39d520005b712858dff502e45): Move namespace to its module
- [98e81ff](https://github.com/quay/clair/commit/98e81ff5f1230f67c3a73055f694a423763062a7): Move keyvalue to keyvalue module
- [ba50d7c](https://github.com/quay/clair/commit/ba50d7c62648471e6e7cf74afe14e9c3268a3a98): Move lock to lock module
- [0b32b36](https://github.com/quay/clair/commit/0b32b36cf7168eef2c005a3d7ec9c3a5996d910b): Move detector to pgsql/detector module
- [c50a233](https://github.com/quay/clair/commit/c50a2339b79c2b5af8552ab6ae4d0e9441df57ac): Split feature.go to table based files in feature module
- [43f3ea8](https://github.com/quay/clair/commit/43f3ea87d86097c81951faf96c000b05445d0947): Move batch queries to corresponding modules
- [a330506](https://github.com/quay/clair/commit/a33050637b4b28f947eb8256cd48ee35d2fe5bfe): Move extra logic in pgsql.go to util folder
- [8bebea3](https://github.com/quay/clair/commit/8bebea3643e294bb11a1766ec450b1e518b0003b): Split testutil.go into multiple files
- [b03f1bc](https://github.com/quay/clair/commit/b03f1bc3a671a28f914ecf012df5250ebf20df03): Fix failed tests
- [ed9c6ba](https://github.com/quay/clair/commit/ed9c6baf4faecad71828dacabc5e804a7f11252b): Fix pgsql test
- [5bf8365](https://github.com/quay/clair/commit/5bf8365f7b5bf493ec3a3c119538c58abaa29209): Prevent inserting invalid entry to database
- [8aae73f](https://github.com/quay/clair/commit/8aae73f1c8cf4dddb91babde813097789eb876f3): Remove unnecessary logs
- [79af05e](https://github.com/quay/clair/commit/79af05e67d6e6f09bd1913dbfe405ebdbd9a9c59): Fix postgres queries for feature_type
- [073c685](https://github.com/quay/clair/commit/073c685c5b085813a9ffbec20fa3c49332f7ec66): Add proper tests for database migration
- [c6c8fce](https://github.com/quay/clair/commit/c6c8fce39a5c28645b9626bc3774bd6b6aadd427): Add feature_type to initial schema
- [a57d806](https://github.com/quay/clair/commit/a57d80671793d48782f8d3777984e99d02dc1fd9): fix unchecked error
- [0c1b80b](https://github.com/quay/clair/commit/0c1b80b2ed54dcbe227f7233468a5bdc66d4a17e): Implement database queries for detector relationship
- [9c49d9d](https://github.com/quay/clair/commit/9c49d9dc5591d62a86632881af8d7a7f15fbf25e): Move queries to corresponding files
- [dca2d4e](https://github.com/quay/clair/commit/dca2d4e597ba837b6f96f3b3e32e23f6b843f9ab): Add detector to database schema
- [5343309](https://github.com/quay/clair/commit/53433090a39195d9df7c920d2e4d142f89abae31): update the query format
- [aea7455](https://github.com/quay/clair/commit/aea74550e14a0f0121fb21a2bba6bb6882c2050f): Expand layer, namespace column widths
### Pkg
- [c3904c9](https://github.com/quay/clair/commit/c3904c9696bddc20a27db9b4142ae704350bbe3f): Add fsutil to contian file system utility functions
### Pkg/Gitutil
- [c2d887f](https://github.com/quay/clair/commit/c2d887f9e99184af502aca7abbe2044d2929e789): init
### Pkg/Grpcutil
- [c4a3254](https://github.com/quay/clair/commit/c4a32543e85a46a94012cfd03fc199854ccf3b44): use cockroachdb cipher suite
- [1ec2759](https://github.com/quay/clair/commit/1ec2759550d6a6bcae7c7252c8718b783426c653): init
### Pkg/Pagination
- [0565938](https://github.com/quay/clair/commit/05659389569549f445eefac650df260ab4f4f05b): add token type
- [d193b46](https://github.com/quay/clair/commit/d193b46449a64a554c3b54dd637a371769bfe195): init
### Pkg/Timeutil
- [45ecf18](https://github.com/quay/clair/commit/45ecf1881521281f09e437c904e1f211dc36e319): init
### README
- [4db72b8](https://github.com/quay/clair/commit/4db72b8c26a5754d61931c2fd5a6ee1829b9f016): fixed issues address
- [6c3b398](https://github.com/quay/clair/commit/6c3b398607f701ac8f016c804f2b2883c0ca1db9): fix IRC copypasta
### Style
- [bd68578](https://github.com/quay/clair/commit/bd68578b8bdd4488e197ccdf6d9322380c6ae7d0): Fix typo in headline
### Tarutil
- [a3a3707](https://github.com/quay/clair/commit/a3a37072b54840aaebde1cd0bba62b8939dafbdc): convert all filename specs to regexps
- [afd7fe2](https://github.com/quay/clair/commit/afd7fe2554d65040b27291d658af21af8f8ae521): allow file names to be specified by regexp
 - fixes [#456](https://github.com/quay/clair/issues/456)### Travis
- [52ecf35](https://github.com/quay/clair/commit/52ecf35ca67558c1bedefb2259e9af9ad9649f9d): fail if not gofmt -s
- [7492aa3](https://github.com/quay/clair/commit/7492aa31baf5b834088ecb8e8bd6ffd7817e5dd7): fail unformatted protos
### Travis
- [870e812](https://github.com/quay/clair/commit/870e8123769a3dd717bfdcd21473a8e691806653): Drop support for postgres 9.4 postgres 9.4 doesn't support ON CONFLICT, which is required in our implementation.
### Update Documentation
- [1105102](https://github.com/quay/clair/commit/1105102b8449fcf20b8db1b1722eeeeece2f33fa): talk about SUSE support
### Update The Ingress To Use ApiVersion
- [435d053](https://github.com/quay/clair/commit/435d05394a9e7895d8daf2804bbe3668e1666981): networking.k8s.io/v1beta1
### Updater
- [a14b372](https://github.com/quay/clair/commit/a14b372838a72d24110b57c6443d784d6fbe4451): fix stuck updater process
### Updater
- [7084a22](https://github.com/quay/clair/commit/7084a226ae9c5a3aed1248ad3d653100d610146c): extract deduplicate function
- [e16d17d](https://github.com/quay/clair/commit/e16d17dda9d29e8fdc33ef9da6a4a8be0e6b648f): remove original RunUpdate()
- [0d41968](https://github.com/quay/clair/commit/0d41968acdeeb2325bf9573a65fd1d05345ba255): reimplement fetch() with errgroup
- [6c5be7e](https://github.com/quay/clair/commit/6c5be7e1c6856fbae55e77c0a3411e7fe4d61f82): refactor to use errgroup
- [2236b0a](https://github.com/quay/clair/commit/2236b0a5c9a094bde2b7979417b9538cb944e726): Add vulnsrc affected feature type
- [0d18a62](https://github.com/quay/clair/commit/0d18a629cab15d57fb7b00777f1537039b69401b): sleep before continuing the lock loop
 - Fixes [#415](https://github.com/quay/clair/issues/415)### Updater,Pkg/Timeutil
- [f64bd11](https://github.com/quay/clair/commit/f64bd117b2fa946c26a2e3368925f6dae8e4a2d3): minor cleanups
### Upgrade To Golang
- [db5dbbe](https://github.com/quay/clair/commit/db5dbbe4e983a4ac827f5b6597aac780c03124b3): 1.10-alpine
### V3
- [88f5069](https://github.com/quay/clair/commit/88f506918b9cb32ab77e41e0cbbe2f9db6e6b358): Analyze layer content in parallel
- [dd23976](https://github.com/quay/clair/commit/dd239762f63702c1800895ee9b86bdda316830ef): Move services to top of the file
- [9f5d1ea](https://github.com/quay/clair/commit/9f5d1ea4e16793ebd9390673aed34855671b5c24): associate feature and namespace with detector
### Vendor
- [4106322](https://github.com/quay/clair/commit/41063221075cea67636f77f58a9d3e112771b835): Update gopkg.in/yaml.v2 package
- [34d0e51](https://github.com/quay/clair/commit/34d0e516e0792ca2d06299a1262e5676d4145f80): Add golang-set dependency
- [55ecf1e](https://github.com/quay/clair/commit/55ecf1e58aa75346ca6c4d702eb31e02ff32ee0e): regenerate after removing graceful
- [1533dd1](https://github.com/quay/clair/commit/1533dd1d51d4f89febd857897addb6dfb6c161e4): updated vendor dir for grpc v2 api
### Vulnmdsrc
- [ce6b008](https://github.com/quay/clair/commit/ce6b00887b1db3a402b1a02bdebb5bcc23d4add0): update NVD URLs
 - Fixes [#575](https://github.com/quay/clair/issues/575)### Vulnsrc
- [72674ca](https://github.com/quay/clair/commit/72674ca871dd2b0a9afdbd9c6a6b50f49a50b20b): Refactor vulnerability sources to use utility functions
### Vulnsrc Rhel
- [bd7102d](https://github.com/quay/clair/commit/bd7102d96304b02ff09077edc16f5f60bd784c8b): handle "none" CVE impact
### Vulnsrc/Alpine
- [c031f8e](https://github.com/quay/clair/commit/c031f8ea0c793ba0462f2b8a204c15ab3a65f1a5): s/pull/clone
- [4c2be52](https://github.com/quay/clair/commit/4c2be5285e1419844377c11484bd684b45948958): avoid shadowing vars
### Vulnsrc/Ubuntu
- [456af5f](https://github.com/quay/clair/commit/456af5f48c8da8325266209e58cec90f4a3f1f68): use new git-based ubuntu tracker
### Vulnsrc_oracle
- [3503ddb](https://github.com/quay/clair/commit/3503ddb96fe412242b84ec28f36a7ddd787b823f): one vulnerability per CVE
 -  [#495](https://github.com/quay/clair/issues/495) -  [#499](https://github.com/quay/clair/issues/499)### Vulnsrc_rhel
- [c4ffa0c](https://github.com/quay/clair/commit/c4ffa0c370e793546dd51ea25fc98961c2d25970): cve impact
- [a90db71](https://github.com/quay/clair/commit/a90db713a2722a80db33e47343c4a4d417f48a0e): add test
- [8b3338e](https://github.com/quay/clair/commit/8b3338ef56b060e27bc3d81124f52bbded315f1a): minor changes
- [4e4e98f](https://github.com/quay/clair/commit/4e4e98f328309d1c0a470388d198fa37c27e47d5): minor changes
- [ac86a36](https://github.com/quay/clair/commit/ac86a3674094f93b71e8736392b7a4707fa972fe): rhsa_ID by default
- [4ab98cf](https://github.com/quay/clair/commit/4ab98cfe54bedcce7880cc03b1c52d5a91811860): one vulnerability by CVE
 - Fixes [#495](https://github.com/quay/clair/issues/495)### Worker
- [23ccd9b](https://github.com/quay/clair/commit/23ccd9b53ba0a8bcf800fecdbd72d5cbefd2ea60): Fix tests for feature_type
- [f0e21df](https://github.com/quay/clair/commit/f0e21df7830e3f8d00498936d0d292ae6ff6765b): fixed duplicated ns and ns not inherited bug
### Workflows
- [f003924](https://github.com/quay/clair/commit/f0039247e1f4c8a2f97b81896782cb802cdeffd8): add go testing matrix
- [ea5873b](https://github.com/quay/clair/commit/ea5873bc8f57eb4d545e0a25a2da868371196926): fix gh-pages argument
- [cec05a3](https://github.com/quay/clair/commit/cec05a35f71dffb6603a2debb14d5388e80643c7): more workflow automation
- [a19407e](https://github.com/quay/clair/commit/a19407e4fd40585b45ffceb507e24c194db78ccc): fix asset name
- [e1902d4](https://github.com/quay/clair/commit/e1902d4d7c1f7d7fdccc6b339736966d2ece0cf6): proper tag name
- [b2d781c](https://github.com/quay/clair/commit/b2d781c2ed50262f4882e34b2585bf99d80fb15b): bad tar flag
### Pull Requests
- Merge pull request [#955](https://github.com/quay/clair/issues/955) from alecmerdler/openapi-fixes
- Merge pull request [#949](https://github.com/quay/clair/issues/949) from alecmerdler/PROJQUAY-494
- Merge pull request [#936](https://github.com/quay/clair/issues/936) from ldelossa/louis/interface-refactor
- Merge pull request [#933](https://github.com/quay/clair/issues/933) from ldelossa/louis/config-and-make
- Merge pull request [#930](https://github.com/quay/clair/issues/930) from ldelossa/louis/middleware-packaging
- Merge pull request [#929](https://github.com/quay/clair/issues/929) from ldelossa/louis/cc-bump-v0.0.17
- Merge pull request [#924](https://github.com/quay/clair/issues/924) from ldelossa/louis/severity-mapping
- Merge pull request [#903](https://github.com/quay/clair/issues/903) from ldelossa/louis/environment-api
- Merge pull request [#897](https://github.com/quay/clair/issues/897) from ldelossa/louis/state-json
- Merge pull request [#890](https://github.com/quay/clair/issues/890) from ldelossa/louis/remove-healthhandler
- Merge pull request [#877](https://github.com/quay/clair/issues/877) from mtougeron/update-ingress-apiversion
- Merge pull request [#873](https://github.com/quay/clair/issues/873) from coreos/code-owners-update
- Merge pull request [#867](https://github.com/quay/clair/issues/867) from andrewsharon/ubuntu19.10
- Merge pull request [#861](https://github.com/quay/clair/issues/861) from thekbb/fix-broken-link-i-missed
- Merge pull request [#856](https://github.com/quay/clair/issues/856) from thekbb/fix-links
- Merge pull request [#860](https://github.com/quay/clair/issues/860) from jzelinskie/bump-v2-master
- Merge pull request [#851](https://github.com/quay/clair/issues/851) from Allda/log-fix
- Merge pull request [#774](https://github.com/quay/clair/issues/774) from Allda/updater_fix
- Merge pull request [#839](https://github.com/quay/clair/issues/839) from noahklein/nvd-status-error
- Merge pull request [#829](https://github.com/quay/clair/issues/829) from peacocb/peacocb-828-dos-on-ancestry-post
- Merge pull request [#831](https://github.com/quay/clair/issues/831) from MVrachev/patch-1
- Merge pull request [#818](https://github.com/quay/clair/issues/818) from vsamidurai/master
- Merge pull request [#822](https://github.com/quay/clair/issues/822) from imlonghao/bullseye
- Merge pull request [#817](https://github.com/quay/clair/issues/817) from ldelossa/remove-detectors
- Merge pull request [#755](https://github.com/quay/clair/issues/755) from Allda/openshift_cert
- Merge pull request [#808](https://github.com/quay/clair/issues/808) from coreos/add-louis
- Merge pull request [#797](https://github.com/quay/clair/issues/797) from jzelinskie/drone
- Merge pull request [#805](https://github.com/quay/clair/issues/805) from ldelossa/remove-ancestry-copy
- Merge pull request [#794](https://github.com/quay/clair/issues/794) from ldelossa/local-dev-readme-update
- Merge pull request [#793](https://github.com/quay/clair/issues/793) from ldelossa/local-dev-clair-db
- Merge pull request [#788](https://github.com/quay/clair/issues/788) from ldelossa/helm-local-dev
- Merge pull request [#780](https://github.com/quay/clair/issues/780) from jzelinskie/CODEOWNERS
- Merge pull request [#779](https://github.com/quay/clair/issues/779) from jzelinskie/mailing-list
- Merge pull request [#773](https://github.com/quay/clair/issues/773) from flumm/disco
- Merge pull request [#671](https://github.com/quay/clair/issues/671) from ericysim/amazon
- Merge pull request [#766](https://github.com/quay/clair/issues/766) from Allda/lock_timeout
- Merge pull request [#742](https://github.com/quay/clair/issues/742) from bluelabsio/path-templating
- Merge pull request [#739](https://github.com/quay/clair/issues/739) from joelee2012/master
- Merge pull request [#749](https://github.com/quay/clair/issues/749) from cnorthwood/tarutil-glob
- Merge pull request [#741](https://github.com/quay/clair/issues/741) from KeyboardNerd/parallel_download
- Merge pull request [#738](https://github.com/quay/clair/issues/738) from Allda/potentialNamespaceAncestry
- Merge pull request [#721](https://github.com/quay/clair/issues/721) from KeyboardNerd/cache
- Merge pull request [#735](https://github.com/quay/clair/issues/735) from jzelinskie/fix-sweet32
- Merge pull request [#722](https://github.com/quay/clair/issues/722) from Allda/feature_ns
- Merge pull request [#724](https://github.com/quay/clair/issues/724) from KeyboardNerd/ref
- Merge pull request [#728](https://github.com/quay/clair/issues/728) from KeyboardNerd/fix
- Merge pull request [#727](https://github.com/quay/clair/issues/727) from KeyboardNerd/master
- Merge pull request [#725](https://github.com/quay/clair/issues/725) from KeyboardNerd/license_test
- Merge pull request [#723](https://github.com/quay/clair/issues/723) from jzelinskie/lock-tx
- Merge pull request [#720](https://github.com/quay/clair/issues/720) from KeyboardNerd/update_ns
- Merge pull request [#695](https://github.com/quay/clair/issues/695) from saromanov/fix-unchecked-error
- Merge pull request [#712](https://github.com/quay/clair/issues/712) from KeyboardNerd/builder
- Merge pull request [#672](https://github.com/quay/clair/issues/672) from KeyboardNerd/source_package/feature_type
- Merge pull request [#685](https://github.com/quay/clair/issues/685) from jzelinskie/updater-cleanup
- Merge pull request [#701](https://github.com/quay/clair/issues/701) from dustinspecker/patch-1
- Merge pull request [#700](https://github.com/quay/clair/issues/700) from traum-ferienwohnungen/master
- Merge pull request [#680](https://github.com/quay/clair/issues/680) from Allda/slices
- Merge pull request [#687](https://github.com/quay/clair/issues/687) from jzelinskie/suse-config
- Merge pull request [#686](https://github.com/quay/clair/issues/686) from jzelinskie/fix-presentations
- Merge pull request [#679](https://github.com/quay/clair/issues/679) from kubeshield/master
- Merge pull request [#506](https://github.com/quay/clair/issues/506) from openSUSE/reintroduce-suse-opensuse
- Merge pull request [#681](https://github.com/quay/clair/issues/681) from Allda/rhel_severity
- Merge pull request [#667](https://github.com/quay/clair/issues/667) from travelaudience/helm-tolerations
- Merge pull request [#656](https://github.com/quay/clair/issues/656) from glb/elsa_CVEID
- Merge pull request [#650](https://github.com/quay/clair/issues/650) from Katee/add-ubuntu-cosmic
- Merge pull request [#653](https://github.com/quay/clair/issues/653) from brosander/helm-dep
- Merge pull request [#648](https://github.com/quay/clair/issues/648) from HaraldNordgren/go_versions
- Merge pull request [#647](https://github.com/quay/clair/issues/647) from KeyboardNerd/spkg/cvrf
- Merge pull request [#644](https://github.com/quay/clair/issues/644) from KeyboardNerd/bug/git
- Merge pull request [#645](https://github.com/quay/clair/issues/645) from Katee/include-cvssv3
- Merge pull request [#646](https://github.com/quay/clair/issues/646) from KeyboardNerd/spkg/model
- Merge pull request [#640](https://github.com/quay/clair/issues/640) from KeyboardNerd/sourcePackage
- Merge pull request [#639](https://github.com/quay/clair/issues/639) from Katee/update-sha1-to-sha256
- Merge pull request [#638](https://github.com/quay/clair/issues/638) from KeyboardNerd/featureTree
- Merge pull request [#633](https://github.com/quay/clair/issues/633) from coreos/roadmap-1
- Merge pull request [#620](https://github.com/quay/clair/issues/620) from KeyboardNerd/feature/detector
- Merge pull request [#627](https://github.com/quay/clair/issues/627) from haydenhughes/master
- Merge pull request [#624](https://github.com/quay/clair/issues/624) from jzelinskie/probot
- Merge pull request [#621](https://github.com/quay/clair/issues/621) from jzelinskie/gitutil
- Merge pull request [#610](https://github.com/quay/clair/issues/610) from MackJM/wip/master_nvd_httputil
- Merge pull request [#499](https://github.com/quay/clair/issues/499) from yebinama/rhel_CVEID
- Merge pull request [#619](https://github.com/quay/clair/issues/619) from KeyboardNerd/sidac/rm_layer
- Merge pull request [#617](https://github.com/quay/clair/issues/617) from jzelinskie/grpc-refactor
- Merge pull request [#614](https://github.com/quay/clair/issues/614) from KeyboardNerd/sidac/simplify
- Merge pull request [#613](https://github.com/quay/clair/issues/613) from jzelinskie/pkg-pagination
- Merge pull request [#611](https://github.com/quay/clair/issues/611) from jzelinskie/drop-graceful
- Merge pull request [#605](https://github.com/quay/clair/issues/605) from KeyboardNerd/sidchen/feature
- Merge pull request [#606](https://github.com/quay/clair/issues/606) from MackJM/wip/master_httputil
- Merge pull request [#607](https://github.com/quay/clair/issues/607) from jzelinskie/gofmt
- Merge pull request [#604](https://github.com/quay/clair/issues/604) from jzelinskie/nvd-urls
- Merge pull request [#601](https://github.com/quay/clair/issues/601) from KeyboardNerd/sidchen/status
- Merge pull request [#594](https://github.com/quay/clair/issues/594) from reasonerjt/fix-alpine-url
- Merge pull request [#578](https://github.com/quay/clair/issues/578) from naibaf0/fix/helmtemplate/configmap/postgresql
- Merge pull request [#586](https://github.com/quay/clair/issues/586) from robertomlsoares/update-helm-chart
- Merge pull request [#582](https://github.com/quay/clair/issues/582) from brosander/helm-alpine-postgres
- Merge pull request [#571](https://github.com/quay/clair/issues/571) from ErikThoreson/nvdupdates
- Merge pull request [#574](https://github.com/quay/clair/issues/574) from hongli-my/fix-nvd-path
- Merge pull request [#572](https://github.com/quay/clair/issues/572) from arno01/multi-stage
- Merge pull request [#540](https://github.com/quay/clair/issues/540) from jzelinskie/document-proto
- Merge pull request [#569](https://github.com/quay/clair/issues/569) from jzelinskie/ubuntu-git
- Merge pull request [#553](https://github.com/quay/clair/issues/553) from qeqar/master
- Merge pull request [#551](https://github.com/quay/clair/issues/551) from usr42/upgrade_to_1.10-alpine
- Merge pull request [#538](https://github.com/quay/clair/issues/538) from jzelinskie/dockerize-protogen
- Merge pull request [#537](https://github.com/quay/clair/issues/537) from tomer-1/patch-1
- Merge pull request [#532](https://github.com/quay/clair/issues/532) from KeyboardNerd/readme_typo
- Merge pull request [#508](https://github.com/quay/clair/issues/508) from joerayme/bug/436
- Merge pull request [#528](https://github.com/quay/clair/issues/528) from KeyboardNerd/helm_typo
- Merge pull request [#522](https://github.com/quay/clair/issues/522) from vdboor/master
- Merge pull request [#521](https://github.com/quay/clair/issues/521) from yebinama/paclair
- Merge pull request [#518](https://github.com/quay/clair/issues/518) from traum-ferienwohnungen/master
- Merge pull request [#513](https://github.com/quay/clair/issues/513) from leandrocr/patch-1
- Merge pull request [#517](https://github.com/quay/clair/issues/517) from KeyboardNerd/master
- Merge pull request [#505](https://github.com/quay/clair/issues/505) from ericchiang/coc
- Merge pull request [#484](https://github.com/quay/clair/issues/484) from odg0318/master
- Merge pull request [#498](https://github.com/quay/clair/issues/498) from bkochendorfer/contributing-link
- Merge pull request [#482](https://github.com/quay/clair/issues/482) from yfoelling/patch-1
- Merge pull request [#487](https://github.com/quay/clair/issues/487) from ajgreenb/db-connection-backoff
- Merge pull request [#488](https://github.com/quay/clair/issues/488) from caulagi/patch-1
- Merge pull request [#485](https://github.com/quay/clair/issues/485) from yebinama/proxy
- Merge pull request [#481](https://github.com/quay/clair/issues/481) from coreos/stable-release-issue-template
- Merge pull request [#479](https://github.com/quay/clair/issues/479) from yebinama/nvd_vectors
- Merge pull request [#477](https://github.com/quay/clair/issues/477) from bseb/master
- Merge pull request [#469](https://github.com/quay/clair/issues/469) from zamarrowski/master
- Merge pull request [#475](https://github.com/quay/clair/issues/475) from dctrud/clair-singularity
- Merge pull request [#467](https://github.com/quay/clair/issues/467) from grebois/master
- Merge pull request [#465](https://github.com/quay/clair/issues/465) from jzelinskie/github
- Merge pull request [#463](https://github.com/quay/clair/issues/463) from brunomcustodio/fix-ingress
- Merge pull request [#459](https://github.com/quay/clair/issues/459) from arthurlm44/patch-1
- Merge pull request [#458](https://github.com/quay/clair/issues/458) from jzelinskie/linux-vulns
- Merge pull request [#450](https://github.com/quay/clair/issues/450) from jzelinskie/move-token
- Merge pull request [#454](https://github.com/quay/clair/issues/454) from InTheCloudDan/helm-tls-option
- Merge pull request [#455](https://github.com/quay/clair/issues/455) from zmarouf/master
- Merge pull request [#449](https://github.com/quay/clair/issues/449) from jzelinskie/helm
- Merge pull request [#447](https://github.com/quay/clair/issues/447) from KeyboardNerd/ancestry_
- Merge pull request [#448](https://github.com/quay/clair/issues/448) from jzelinskie/woops
- Merge pull request [#444](https://github.com/quay/clair/issues/444) from jzelinskie/docs-refresh
- Merge pull request [#432](https://github.com/quay/clair/issues/432) from KeyboardNerd/ancestry_
- Merge pull request [#442](https://github.com/quay/clair/issues/442) from arminc/add-integration-clari-scanner
- Merge pull request [#433](https://github.com/quay/clair/issues/433) from mssola/portus-integration
- Merge pull request [#408](https://github.com/quay/clair/issues/408) from KeyboardNerd/grpc
- Merge pull request [#423](https://github.com/quay/clair/issues/423) from jzelinskie/sleep-updater
- Merge pull request [#418](https://github.com/quay/clair/issues/418) from KeyboardNerd/multiplens
- Merge pull request [#410](https://github.com/quay/clair/issues/410) from KeyboardNerd/xforward
- Merge pull request [#416](https://github.com/quay/clair/issues/416) from tianon/debian-buster
- Merge pull request [#413](https://github.com/quay/clair/issues/413) from transcedentalia/master
- Merge pull request [#403](https://github.com/quay/clair/issues/403) from KeyboardNerd/multiplens
- Merge pull request [#407](https://github.com/quay/clair/issues/407) from swestcott/kubernetes-config-fix
- Merge pull request [#394](https://github.com/quay/clair/issues/394) from KeyboardNerd/multiplens
- Merge pull request [#382](https://github.com/quay/clair/issues/382) from caipre/patch-1


<a name="v2.1.4"></a>
## [v2.1.4] - 2020-05-28

<a name="qui-gon"></a>
## [qui-gon] - 2020-05-28
### Api
- [546fd93](https://github.com/quay/clair/commit/546fd936739d6875b818a9e5ab9b84b3e860794c): use cockroachdb cipher suite
### Api/V1
- [d8560e2](https://github.com/quay/clair/commit/d8560e24c6b111857eadc6b16beb7c52bf9715ec): remove debug statement
### Clair
- [0ef7cee](https://github.com/quay/clair/commit/0ef7cee405354032fd3b22d83663ce5fe70d5e28): remove vendor directory
- [8483a69](https://github.com/quay/clair/commit/8483a696f6dba0add8443d0cbfcd305bdef2c20d): rewrite imports
- [7bc8980](https://github.com/quay/clair/commit/7bc8980e0f1bc6b5ec63ae5230c956fac12eed9e): create module
### Database
- [9a45205](https://github.com/quay/clair/commit/9a452050c85acaa573403edffff1c13921cd460a): add ubuntu cosmic mapping
- [f882e1c](https://github.com/quay/clair/commit/f882e1c2109383fd8a46c33b86c8960d84b5fc90): add ubuntu bionic namespace mapping
### Dockerfile
- [5fed354](https://github.com/quay/clair/commit/5fed3540412d183237400af564f9774e75f4d8b8): bump to Go 1.13
### Ext/Featurens
- [8aeb337](https://github.com/quay/clair/commit/8aeb3374717e643eb7e81f95f0fda61de7042e4d): add support for RHEL8
 - Fixes [#889](https://github.com/quay/clair/issues/889)### Ext/Vulnsrc/Rhel
- [ee4380f](https://github.com/quay/clair/commit/ee4380f51a92b6ec5c29e62829c7d202cb7c3c30): s/Warning/Warningf
### Ext/Vulnsrc/Ubuntu
- [d1cadb4](https://github.com/quay/clair/commit/d1cadb4cdc4784790338aa25e755c79404966791): updated tracker src
 - Fixes [#524](https://github.com/quay/clair/issues/524)### Feat
- [d82e9b0](https://github.com/quay/clair/commit/d82e9b0e20345e29178bd277a1305037af870d02): support ubuntu 20.04 ([#987](https://github.com/quay/clair/issues/987))
 -  [#987](https://github.com/quay/clair/issues/987)- [ad6be9c](https://github.com/quay/clair/commit/ad6be9ce0191e70af9672d5aa4b69217c5606082): backport ubuntu 19.10 ([#977](https://github.com/quay/clair/issues/977))
 -  [#977](https://github.com/quay/clair/issues/977)### Featurens
- [e650d58](https://github.com/quay/clair/commit/e650d58583aa48a03f5e9f0ce2621be54cfcee40): Ensure RHEL is correctly identified
 - Fixes [#436](https://github.com/quay/clair/issues/436)### Imgfmt
- [a80ca55](https://github.com/quay/clair/commit/a80ca551cf83e7c3911e68b22f9b05addb74f911): download using http proxy from env
### Rhel
- [5731f5d](https://github.com/quay/clair/commit/5731f5d23c4da2d3953d801867e67b4ef1eab5df): make as much progress as possible on updates
### Use Golang
- [ad98b97](https://github.com/quay/clair/commit/ad98b97a6de6dd4f7cf22c419db316e8676b1bf7): 1.10-alpine with v2.0.2
### Vulnmdsrc
- [5e4c36a](https://github.com/quay/clair/commit/5e4c36aad537b4a14b96214074f97b293261bba7): update NVD URLs
 - Fixes [#575](https://github.com/quay/clair/issues/575)### Pull Requests
- Merge pull request [#898](https://github.com/quay/clair/issues/898) from rpnguyen/ubi8-backport-release-2.0
- Merge pull request [#895](https://github.com/quay/clair/issues/895) from andrewsharon/release-2.0
- Merge pull request [#887](https://github.com/quay/clair/issues/887) from ldelossa/louis/rhel-import-fix
- Merge pull request [#875](https://github.com/quay/clair/issues/875) from quay/v2-module
- Merge pull request [#876](https://github.com/quay/clair/issues/876) from reasonerjt/nvd-json-2.0
- Merge pull request [#859](https://github.com/quay/clair/issues/859) from jzelinskie/v2-bump-go
- Merge pull request [#846](https://github.com/quay/clair/issues/846) from ErikThoreson/v2.0.9-nvdfix
- Merge pull request [#840](https://github.com/quay/clair/issues/840) from glb/bugfix-231-release-2.0
- Merge pull request [#823](https://github.com/quay/clair/issues/823) from imlonghao/release-2.0-bullseye
- Merge pull request [#769](https://github.com/quay/clair/issues/769) from roxspring/backport/[gh-630](https://github.com/quay/clair/issues/630)-dumb-init
- Merge pull request [#776](https://github.com/quay/clair/issues/776) from flumm/release-2.0-disco
- Merge pull request [#736](https://github.com/quay/clair/issues/736) from jzelinskie/fix-sweet32-v2
- Merge pull request [#615](https://github.com/quay/clair/issues/615) from reasonerjt/updater-loop-2.0
- Merge pull request [#603](https://github.com/quay/clair/issues/603) from MackJM/httpclient
- Merge pull request [#599](https://github.com/quay/clair/issues/599) from reasonerjt/fix-alpine-url-2.0
- Merge pull request [#530](https://github.com/quay/clair/issues/530) from meringu/patch-1
- Merge pull request [#568](https://github.com/quay/clair/issues/568) from MackJM/release-2.0
- Merge pull request [#562](https://github.com/quay/clair/issues/562) from ninjaMog/ubuntu-tracker-update
- Merge pull request [#565](https://github.com/quay/clair/issues/565) from ninjaMog/nvd-endpoint-update
- Merge pull request [#554](https://github.com/quay/clair/issues/554) from usr42/release-2.0_go1.10
- Merge pull request [#531](https://github.com/quay/clair/issues/531) from bison/oracle-regex
- Merge pull request [#423](https://github.com/quay/clair/issues/423) from jzelinskie/sleep-updater
- Merge pull request [#407](https://github.com/quay/clair/issues/407) from swestcott/kubernetes-config-fix
- Merge pull request [#413](https://github.com/quay/clair/issues/413) from transcedentalia/master
- Merge pull request [#416](https://github.com/quay/clair/issues/416) from tianon/debian-buster


<a name="v4.0.0-alpha.6"></a>
## [v4.0.0-alpha.6] - 2020-05-01
### Go.Mod
- [ef5fbc4](https://github.com/quay/clair/commit/ef5fbc4d6dcf877a05a5a12b6dd2a7a7c50568cf): bump claircore version for severity fix

<a name="v4.0.0-alpha.5"></a>
## [v4.0.0-alpha.5] - 2020-04-30
### Config
- [a93271b](https://github.com/quay/clair/commit/a93271b3be48ebe617363751d64e26840678583e): implement base64 -> []byte conversion ([#984](https://github.com/quay/clair/issues/984))
 -  [#984](https://github.com/quay/clair/issues/984)
<a name="v4.0.0-alpha.4"></a>
## [v4.0.0-alpha.4] - 2020-04-20
### *
- [74efdf6](https://github.com/quay/clair/commit/74efdf6b51e3e625ca9f122e7aa88e88f4708a68): update roadmap
 - Fixes [#626](https://github.com/quay/clair/issues/626)- [ce15f73](https://github.com/quay/clair/commit/ce15f73501b758b3d24e06753ce62123d0a36920): gofmt -s
- [5caa821](https://github.com/quay/clair/commit/5caa821c80a4efa2986728d6f223552b44f6ce15): remove bzr dependency
- [033cae7](https://github.com/quay/clair/commit/033cae7d358b2f7b866da7d9be3367d902cdf035): regenerate bill of materials
- [1f5bc26](https://github.com/quay/clair/commit/1f5bc26320bc58676d88c096404a8503dca7a4d8): rename example config
### .Github
- [9b1f205](https://github.com/quay/clair/commit/9b1f2058338b8aeaa5441091b4920731235f1353): add stale and issue template enforcement
### API
- [0151dba](https://github.com/quay/clair/commit/0151dbaef81cae54aa95dd8abf36d58414de2b26): change api port to api addr, rename RunV2 to Run.
 - Fixes [#446](https://github.com/quay/clair/issues/446)- [a378cb0](https://github.com/quay/clair/commit/a378cb070cb9ec56f363ec08adb8e023bfb3994e): drop v1 api, changed v2 api for Clair v3.
### All
- [fbbffcd](https://github.com/quay/clair/commit/fbbffcd2c2a34d8a6128a06a399234b444c74d09): add opentelemetry hooks
### Api
- [69c0c84](https://github.com/quay/clair/commit/69c0c84348c74749cd1d12ee4e4959991621a59d): Rename detector type to DType
- [48427e9](https://github.com/quay/clair/commit/48427e9b8808f86929ffb905952395c91644f04e): Add detectors for RPC
- [dc6be5d](https://github.com/quay/clair/commit/dc6be5d1b073d87b2405d84d33f5bb5f6ced490e): remove handleShutdown func
- [30644fc](https://github.com/quay/clair/commit/30644fcc01df7748d8e2ae15c427f01702dd4e90): remove dependency on graceful
- [58022d9](https://github.com/quay/clair/commit/58022d97e3ec7194e89522c9adb866a85c704378): renamed V2 API to V3 API for consistency.
- [c6f0eaa](https://github.com/quay/clair/commit/c6f0eaa3c82197f15371b4d2c8af686d8a7a569f): fix remote addr shows reverse proxy addr problem
- [a4edf38](https://github.com/quay/clair/commit/a4edf385663b2e412e1fd64f7d45e1ee01749798): v2 api with gRPC and gRPC-gateway
 - Fixes [#98](https://github.com/quay/clair/issues/98)### Api,Database
- [a75b8ac](https://github.com/quay/clair/commit/a75b8ac7ffe3ccd7ff9c4718e547c6c5103e9747): updated version_format documentation.
 - Fixes [#514](https://github.com/quay/clair/issues/514)### Api/V3
- [32b11e5](https://github.com/quay/clair/commit/32b11e54eb287ed0d686ba72fe413b773b748a38): Add feature type to API feature
- [f550dd1](https://github.com/quay/clair/commit/f550dd16a01edc17de0e3c658c5f7bc25639a0a1): remove dependency on google empty message
- [d7a751e](https://github.com/quay/clair/commit/d7a751e0d4298442883fde30ee37c529b2bb3719): prototool format
### Api/V3/Clairpb
- [6b9f668](https://github.com/quay/clair/commit/6b9f668ea0b657526b35008f8efd9c8f0a46df9b): document and regenerate protos
- [ec5014f](https://github.com/quay/clair/commit/ec5014f8a13605458faf1894bb905f2123ded0a7): regen protobufs
- [389b6e9](https://github.com/quay/clair/commit/389b6e992790f6e28b77ca5979c0589e43dbe40a): generate protobufs in docker
### CODEOWNERS
- [f20a72c](https://github.com/quay/clair/commit/f20a72c34ef80b4c1dee7b9984aa713f82e6c342): add Louis
- [abf6e74](https://github.com/quay/clair/commit/abf6e74790294bb765a68765afa9d8e73c3fab22): init
### Clair
- [fa95f5d](https://github.com/quay/clair/commit/fa95f5d80c86f3e916661156f99dac6fcc91a3bb): bump claircore version
- [42b1ba9](https://github.com/quay/clair/commit/42b1ba9f91f9174397280152eca5a0096342019e): use Etag header to communicate indexer state change
- [fd5993f](https://github.com/quay/clair/commit/fd5993f9765cc23355e5895105a15b71e5eb3156): add "mode" argument
- [4091329](https://github.com/quay/clair/commit/409132958e0538046e3481d3197e192316b06d91): change version information
- [8cbddd1](https://github.com/quay/clair/commit/8cbddd187e7065315417ca2f86a5e261f3d92651): better introspection server defaults
- [c097454](https://github.com/quay/clair/commit/c097454c182daa68427918d0ba2fe24bbdf6ed71): logging and introspection setup
- [a003aa4](https://github.com/quay/clair/commit/a003aa414ead82a32b24a977e301e5697718ec43): add configuration for introspection
- [d9db7c1](https://github.com/quay/clair/commit/d9db7c153ce80d3d47bbb342bd6ef873bc2954b4): use "Updaters" config option
- [48daeae](https://github.com/quay/clair/commit/48daeaeacc5a1444a07cc6ddc20b4b800d8b43be): fix header casing
- [fb28e56](https://github.com/quay/clair/commit/fb28e569da21f847c7bbc2f97807485ea007e698): remove os.Exit call on clean shutdown
- [8039e1c](https://github.com/quay/clair/commit/8039e1c95f56353e47aaa5ed66b80244ac2d2cad): add authorization checking
- [1b41336](https://github.com/quay/clair/commit/1b41336265126c23b152d18c28ea6e0fd3d6baf8): update claircore to 0.0.14
- [791610f](https://github.com/quay/clair/commit/791610f1c893fc76d6fcf350a7383a2479aa723a): remove goautoneg
- [7b6ef7d](https://github.com/quay/clair/commit/7b6ef7da8c125111ec37fe61206dce1ee25408ec): reset writers when pulled from pool
- [ad73d74](https://github.com/quay/clair/commit/ad73d747fcc6c674752eaf5ae7ccdcb6fa4daead): remove vendor directory
- [00eff59](https://github.com/quay/clair/commit/00eff59af580893d3e045333fa095d3507a528f1): rewrite imports
- [1f2ceeb](https://github.com/quay/clair/commit/1f2ceeb8f7fcf9e8ce94206f76a8b610b84424ca): create module
- [c6497dd](https://github.com/quay/clair/commit/c6497dda0a95a3309dc649761243250634a31d40): Fix namespace update logic
- [465687f](https://github.com/quay/clair/commit/465687fa94b4e9fe00e0ba1190989d0d454c14ab): Add more logging on ancestry cache hit
- [5b23764](https://github.com/quay/clair/commit/5b2376498bbc0ea0a893754887defce4daa59daa): Use builder pattern for constructing ancestry
- [0283240](https://github.com/quay/clair/commit/028324014ba3b7111e4e4533d6a8d4d99bb1fd72): Implement worker detector support
### Clair Logic, Extensions
- [fb32dcf](https://github.com/quay/clair/commit/fb32dcfa58077dadd8bfbf338c4aa342d5e9ef85): updated mock tests, extensions, basic logic
### Clairctl
- [2e68178](https://github.com/quay/clair/commit/2e6817881eed93af469abd7e16839961aa812469): remove log.Lmsgprefix
- [0282f68](https://github.com/quay/clair/commit/0282f68bf381a5b0a592079819e38b3d88296f92): report command
- [f1c4798](https://github.com/quay/clair/commit/f1c4798bb10292fe1f14d71691ab33d4ea5a2ae9): start on clair cli tool
### Client
- [1ba6891](https://github.com/quay/clair/commit/1ba68911163afb001cd89cf84862506f008edcf4): add differ and refactor client
### Cmd/Clair
- [b20482e](https://github.com/quay/clair/commit/b20482e0aebcf2cc67f61e8ff821ddcdffc53ac7): document constants
### Config
- [2ed3c2c](https://github.com/quay/clair/commit/2ed3c2c800bb9639618a86f33916625b0a595f49): rework auth config
- [b2666e5](https://github.com/quay/clair/commit/b2666e57202d7c690a40d7c86975c13e0b3db56e): set a canonical default port
- [4f23269](https://github.com/quay/clair/commit/4f232698b0178ef9d1a3cde01b6ff40e47659cfa): add updaters and tracing options
- [162e8cd](https://github.com/quay/clair/commit/162e8cdafc66be28b021f83da736a2b612ddda99): enable suse updater
- [0609ed9](https://github.com/quay/clair/commit/0609ed964b0673806462a24147e6028da85d8a38): removed worker config
### Contrib
- [76b9f8e](https://github.com/quay/clair/commit/76b9f8ea05b110d1ff659964fc9126824ec28b17): replace old k8s manifests with helm
- [ac1cdd0](https://github.com/quay/clair/commit/ac1cdd03c9e31ddaea627e076704f38a0d4719fb): move grafana and compose here
### Contrib/Helm/Clair
- [13be17a](https://github.com/quay/clair/commit/13be17a69082d30996d53d3087b7265007bae555): fix the ingress template
### Convert
- [f2ce832](https://github.com/quay/clair/commit/f2ce8325b975a15c977654d3be1084ad1e890bf3): return nil when detector is empty
### Database
- [506698a](https://github.com/quay/clair/commit/506698a4246e24bb3a72bd626d95bd47dc38beb8): add mapping for Ubuntu Eoan (19.10)
- [1ddc053](https://github.com/quay/clair/commit/1ddc0532e4be8dac02e171b986da51deaffbb636): Handle FindAncestryAndRollback datastore.Begin() error
 - Fixes [#828](https://github.com/quay/clair/issues/828)- [6617f56](https://github.com/quay/clair/commit/6617f560cc9ce90eece08aca29841827c72ca5c2): Rename affected type to feature type (for Amazon Linux updater)
- [3fafb73](https://github.com/quay/clair/commit/3fafb73c4fe0e9fbc03d1c5657b57ba0ca04c000): Split models.go into different files each contains one model
- [1b9ed99](https://github.com/quay/clair/commit/1b9ed99646e492a27e982ae34dea7c6fc7273c52): Move db logic to dbutil
- [961c7d4](https://github.com/quay/clair/commit/961c7d4680c58e3b01eedb4361a3fa57a1f9a904): add test for lock expiration
- [a4e7873](https://github.com/quay/clair/commit/a4e7873d1432b9b593f2e9dc44a02f2badea9002): make locks SOI & add Extend method
- [5fa1ac8](https://github.com/quay/clair/commit/5fa1ac89b9946f2e32ac666080b4f78ad1f9bbfa): Add StorageError type
- [f616753](https://github.com/quay/clair/commit/f61675355e7a296989e778f37257e6e416e6f208): Update feature model Remove source name/version fields Add Type field to indicate if it's binary package or source package
- [7dd989c](https://github.com/quay/clair/commit/7dd989c0f21bc5c4cb390f575dca9973829ef9ce): Rename affected Type to feature type
- [00eed77](https://github.com/quay/clair/commit/00eed77b451b8913771feef7a40067dd246d7872): Add feature_type database model
- [dd91597](https://github.com/quay/clair/commit/dd91597f19dae90e8b671d2c80004f0a28dc177c): remove FindLock from mock
- [399deab](https://github.com/quay/clair/commit/399deab1005b7c3541ad0dacb52bd7961b5167cc): remove FindLock()
- [300bb52](https://github.com/quay/clair/commit/300bb52696036dce96ee360f4431837e6ee452a2): add FindLock dbutil
- [4fbeb9c](https://github.com/quay/clair/commit/4fbeb9ced594b17aeee3e022f87ed7345376f232): add (Acquire|Release)Lock dbutils
- [6c682da](https://github.com/quay/clair/commit/6c682da3e138e0a7d09dadae7040d8cebba88e2b): add mapping for Ubuntu Cosmic (18.10)
- [a3f7387](https://github.com/quay/clair/commit/a3f7387ff146226f31a03906591cbb0d0e64cb44): Add FindKeyValue function wrapper
- [00fadfc](https://github.com/quay/clair/commit/00fadfc3e3da8c25b6c0c3f13d48017173a45a93): Add affected feature type
- [f759dd5](https://github.com/quay/clair/commit/f759dd54c028e8b39fd1e21c8c70ebda567aa7cd): Replace Parent Feature with source metadata
- [3fe894c](https://github.com/quay/clair/commit/3fe894c5ad7b33223be4a6d52bc0d88fc0fd3a18): Add parent feature pointer to Feature struct
- [a3e9b5b](https://github.com/quay/clair/commit/a3e9b5b55d13921b61e2f92a1ade9392b6e7d7a0): rename utility functions with commit/rollback
- [e657d26](https://github.com/quay/clair/commit/e657d26313b1b91fe4dab17298597119dc919cd2): move dbutil and testutil to database from pkg
- [db2db8b](https://github.com/quay/clair/commit/db2db8bbe8a17e10c9fb365196f88d552e70e91d): Update database model and interface for detectors
- [e160616](https://github.com/quay/clair/commit/e160616723643beff99363b7b385fd4b8ce6802a): Use LayerWithContent as Layer
- [ff93039](https://github.com/quay/clair/commit/ff9303905beb2e2f28d2a33e3fc232cd846b5963): changed Notification interface name
- [a5c6400](https://github.com/quay/clair/commit/a5c6400065a873f6ae14d50b73550dc07239d7bf): postgres implementation with tests.
### Database/Pgsql
- [4491bed](https://github.com/quay/clair/commit/4491bedf2e284007fa7f527bf264dc98c937d820): move token lib
### Datastore
- [57b146d](https://github.com/quay/clair/commit/57b146d0d808a29db9f299778fb5527cd0974b06): updated for Clair V3, decoupled interfaces and models
### Dockerfile
- [2ca92d0](https://github.com/quay/clair/commit/2ca92d00754b1d1859e9d6f3169d67d6b96d6bee): bump Go to 1.13
### Dockerfile
- [33da12a](https://github.com/quay/clair/commit/33da12a3bb9a28fdbcc6302caa4212d38a2acbbb): run as unprivledged user by default
- [e56b95a](https://github.com/quay/clair/commit/e56b95aca0085067f91f90e3b32dab9d04e7fb48): use environment variables
- [33b3224](https://github.com/quay/clair/commit/33b3224df13b9c2aa8b0281f120997abce82eaf9): update for clair v4
### Docs
- [49b5621](https://github.com/quay/clair/commit/49b5621d738978c94e8d311775bba48a1daafc7e): fix typo in running-clair
- [9ee2ff4](https://github.com/quay/clair/commit/9ee2ff4877db15a5ad8ae24afcb8f02f0e8289cf): add troubleshooting about kernel packages
- [3f91bd2](https://github.com/quay/clair/commit/3f91bd2a9bc40bd7b6f4e5a5a8a533de383f3554): turn README into full articles
### Documentation
- [fe324a5](https://github.com/quay/clair/commit/fe324a58e6be8c36da74afcd5487d0da4a547d5b): start writing v4-specific docs
- [c1a58bf](https://github.com/quay/clair/commit/c1a58bf9224bbcd7e0f02ea4065650d220654f29): add new 3rd party tool
### Documentation
- [3e6896c](https://github.com/quay/clair/commit/3e6896c6a4e5cdd04d91927d762b332b62e1d4fe): fix links to presentations
 - Closes [#661](https://github.com/quay/clair/issues/661) - Closes [#665](https://github.com/quay/clair/issues/665) - Closes [#560](https://github.com/quay/clair/issues/560)### Driver
- [5c58575](https://github.com/quay/clair/commit/5c5857548d43fa866d46a4c98309b2dfa88be418): Add proxy support
### Drone
- [0fd9cd3](https://github.com/quay/clair/commit/0fd9cd3b59bd42ef0e508f0f415028a0ee8fa44f): remove broken drone CI
- [352f738](https://github.com/quay/clair/commit/352f73834e7bdef31dc5e3a715133f5c47947764): init
### Ext
- [25078ac](https://github.com/quay/clair/commit/25078ac838920e4010ecdbe4546af0d4b502dabd): add CleanAll() utility functions
- [081ae34](https://github.com/quay/clair/commit/081ae34af146365146cf4548a8a0afa293e15695): remove duplicate vectorValuesToLetters definition
- [4f0da12](https://github.com/quay/clair/commit/4f0da12b123ec543a58936c0f7226254e411cc00): pass through CVSSv3 impact and exploitability score
- [8efc3e4](https://github.com/quay/clair/commit/8efc3e40382287e88714fdcf634a79e6347b6157): remove unneeded use of init()
- [699d114](https://github.com/quay/clair/commit/699d1143e5ab2a673d0f83249f3268cfebaf3e57): fixup incorrect copyright year
- [b81e445](https://github.com/quay/clair/commit/b81e4454fbb7f3dcec4a2dd6064820bf0c6321f2): Parse CVSSv3 data from JSON NVD feed
- [14277a8](https://github.com/quay/clair/commit/14277a8f5d95799bb651c194785dd04e75a08ee1): Add JSON NVD parsing tests
- [aab46f5](https://github.com/quay/clair/commit/aab46f5658cf5a75262945033cb41d93af5f2131): Parse NVD JSON feed instead of XML
- [8d5a013](https://github.com/quay/clair/commit/8d5a0131c48d0812d1dd53b1af8e24ae4e51c4ba): Use SHA256 instead of SHA1 for fingerprinting
- [53bf19a](https://github.com/quay/clair/commit/53bf19aecfcccb367bc359a2dd6d7320fa4e4855): Lister and Detector returns detector info with detected content
### Ext/Featurefmt
- [1c40e7d](https://github.com/quay/clair/commit/1c40e7d01697f5680408f138e6974266c6530cb1): Refactor featurefmt testing code
### Ext/Featurefmt/Apk
- [2cc61f9](https://github.com/quay/clair/commit/2cc61f9fc0edc42d2c0fda71471208e3faba507d): Extract origin package information from database
### Ext/Featurefmt/Dpkg
- [4ac0466](https://github.com/quay/clair/commit/4ac046642ffea9fb60af455b9d22d19cd4408f32): Extract source package metadata
### Ext/Featurefmt/Rpm
- [a057e4a](https://github.com/quay/clair/commit/a057e4a943dc1a2dc1898b67435b05417725402e): Extract source package from rpm database
### Feature
- [90f5592](https://github.com/quay/clair/commit/90f5592095f74e9704193f4362c494571667b326): replace arrays with slices
### Featurefmt
- [34c2d96](https://github.com/quay/clair/commit/34c2d96b3685a927749536017add6538578fb2df): Extract PotentialNamespace
- [0e0d8b3](https://github.com/quay/clair/commit/0e0d8b38bba4c62552c98ad5b98242ddd2c3464b): Extract source packages and binary packages The featurefmt now extracts both binary packages and source packages from the package manager infos.
- [9561d62](https://github.com/quay/clair/commit/9561d623c29394dddca0823721d7d3622b3dec65): use namespace's versionfmt to specify listers
### Featurens
- [947a8aa](https://github.com/quay/clair/commit/947a8aa00c6f72a20e7fca63993dafaf3185fdc4): Ensure RHEL is correctly identified
 - Fixes [#436](https://github.com/quay/clair/issues/436)- [50437f3](https://github.com/quay/clair/commit/50437f32a1d7d609cfd5e6eb3f0bbf180099fc05): fix detecting duplicated namespaces problem
- [75d5d40](https://github.com/quay/clair/commit/75d5d40d796f4233a58c16443614933c8b326d49): added multiple namespace testing for namespace detector
### Fix
- [4e49aaf](https://github.com/quay/clair/commit/4e49aaf34647ab636595c1ba631efa0cea56ceac): lock updater - return correct bool value
### Github
- [6a42aba](https://github.com/quay/clair/commit/6a42aba3aa7c73627fd73da3d57dd233de1184e8): add mailing list!
- [c7a67ed](https://github.com/quay/clair/commit/c7a67edf5d8957ff05391770d6800e9e83b6b0a9): add issue template stable release notice
- [f6cac47](https://github.com/quay/clair/commit/f6cac4733a7545736d5875f0b36324481098d471): add issue template
- [24ca12b](https://github.com/quay/clair/commit/24ca12bdecfcbc2d7797a01dcde87fea44dad7c8): move CONTRIBUTING to github dir
### Gitutil
- [11b67e6](https://github.com/quay/clair/commit/11b67e612c3703af63a4c63364ea60445077a2a7): Fix git pull on non-git repository directory
 - Fixes [#641](https://github.com/quay/clair/issues/641)### Glide
- [165c397](https://github.com/quay/clair/commit/165c397f169409dfce9b41459d5845e774c8ef81): add errgroup and regenerate vendor
### Go.Mod
- [ad58dd9](https://github.com/quay/clair/commit/ad58dd9758726e488b5c60a47b602f1492de7204): update to latest claircore
### HELM
- [81430ff](https://github.com/quay/clair/commit/81430ffbb252990ebfd74b0bba284c7564b69dae): also add option for nodeSelector
- [6a94d8c](https://github.com/quay/clair/commit/6a94d8ccd267cc428dd2161bb1e5b71dd3cd244f): add option for tolerations
### Helm
- [690d26e](https://github.com/quay/clair/commit/690d26edbac2605b19900549b70d74fa47bdfef9): change postgresql connection string format in configmap template
 - Fixes [#561](https://github.com/quay/clair/issues/561)- [7a06a7a](https://github.com/quay/clair/commit/7a06a7a2b4a68c2567a5bcc41c497fdb9d8d2c15): Fixed a typo in maintainers field.
### Helm
- [710c655](https://github.com/quay/clair/commit/710c65530f4524693e6a863075b4d3760901a3bc): allow for ingress path configuration in values.yml
### Helm Chart
- [bc6f37f](https://github.com/quay/clair/commit/bc6f37f1ae0df5a7c01184ef1483a889e82e86ba): Use Secret for config file. Fix some minor issues
 - Fixes [#581](https://github.com/quay/clair/issues/581)### Httptransport
- [5683018](https://github.com/quay/clair/commit/5683018f2e7d091897a238aa82e88da56941fee8): serve OpenAPI definition
- [e783062](https://github.com/quay/clair/commit/e783062b41af06eed250d289a2dfa43a4b6aeb25): wire in update endpoints
- [9cd6cab](https://github.com/quay/clair/commit/9cd6cabf62b60bd47bd2f6546cd5a806f1d79ad3): report write errors via trailer
### Imagefmt
- [891ce16](https://github.com/quay/clair/commit/891ce1697d0e53e253001d0ae7620f31b886618c): Move layer blob download logic to blob.go
### Indexer
- [500355b](https://github.com/quay/clair/commit/500355b53c213193147e653b147afc3036ea2125): add basic latency summary
- [8953724](https://github.com/quay/clair/commit/8953724bab392fa3897c2fae62b5df6e9567047c): QoL changes to headers
- [741fc2c](https://github.com/quay/clair/commit/741fc2c4bacb7e5651b05b298257a41ec7558858): HTTP correctness changes
- [10d2f54](https://github.com/quay/clair/commit/10d2f5472efc414846b56edf9d77a69246ea06b2): rename index endpoint
- [ac0a0d4](https://github.com/quay/clair/commit/ac0a0d49424f1f19b5044ea84a245e3139b5adb3): add Accept-Encoding aware middleware
- [3a9ca8e](https://github.com/quay/clair/commit/3a9ca8e57a041bdd78d5e37a904a1ff5942befd8): add State method
### Layer
- [015a79f](https://github.com/quay/clair/commit/015a79fd5a077a3e8340f8cef8610512f53ef053): replace arrays with slices
### Mapping
- [07a08a4](https://github.com/quay/clair/commit/07a08a4f53cab155814eadde44a847e2389b5bcc): add ubuntu mapping
 - Fixes [#552](https://github.com/quay/clair/issues/552)### Matcher
- [15c098c](https://github.com/quay/clair/commit/15c098c48cac6e87b82a4af4b5914aef0ab83310): add basic latency summary
- [0017946](https://github.com/quay/clair/commit/0017946470397c252b1934d1637fe7b1d01fe280): return OK instead of Created
### Nvd
- [e953a25](https://github.com/quay/clair/commit/e953a259b008042d733a4c0aadc9b85d1bedf251): fix the name of a field
### Openapi
- [1949ec3](https://github.com/quay/clair/commit/1949ec3a22a5d2dd5cc30a5fccb99c49a657677a): lint and update Layer
### PgSQL
- [57a4f97](https://github.com/quay/clair/commit/57a4f977803e5eb0d5ddb23e6d54e8490efe89c9): fixed invalidating vulnerability cache query.
### Pgsql
- [0731df9](https://github.com/quay/clair/commit/0731df972c5270d2540411cc2ae1b4f3c9b36dc6): Remove unused test code
- [dfa07f6](https://github.com/quay/clair/commit/dfa07f6d860c59ba2b2cc4909d38f650e9d3969b): Move notification to its module
- [921acb2](https://github.com/quay/clair/commit/921acb26fe875ed18c95b2f62a73fa3e1a8aa355): Split vulnerability.go to files in vulnerability module
- [7cc83cc](https://github.com/quay/clair/commit/7cc83ccbc5b4e34762d10343c2bc989a14fddebc): Split ancestry.go to files in ancestry module
- [497b79a](https://github.com/quay/clair/commit/497b79a293ce9d07f34ffd8ea51264c8ae6bd84c): Add test for migrations
- [ea418cf](https://github.com/quay/clair/commit/ea418cffd474252d9a59881677daffbdaa507768): Split layer.go to files in layer module
- [176c69e](https://github.com/quay/clair/commit/176c69e59dfbd4b39d520005b712858dff502e45): Move namespace to its module
- [98e81ff](https://github.com/quay/clair/commit/98e81ff5f1230f67c3a73055f694a423763062a7): Move keyvalue to keyvalue module
- [ba50d7c](https://github.com/quay/clair/commit/ba50d7c62648471e6e7cf74afe14e9c3268a3a98): Move lock to lock module
- [0b32b36](https://github.com/quay/clair/commit/0b32b36cf7168eef2c005a3d7ec9c3a5996d910b): Move detector to pgsql/detector module
- [c50a233](https://github.com/quay/clair/commit/c50a2339b79c2b5af8552ab6ae4d0e9441df57ac): Split feature.go to table based files in feature module
- [43f3ea8](https://github.com/quay/clair/commit/43f3ea87d86097c81951faf96c000b05445d0947): Move batch queries to corresponding modules
- [a330506](https://github.com/quay/clair/commit/a33050637b4b28f947eb8256cd48ee35d2fe5bfe): Move extra logic in pgsql.go to util folder
- [8bebea3](https://github.com/quay/clair/commit/8bebea3643e294bb11a1766ec450b1e518b0003b): Split testutil.go into multiple files
- [b03f1bc](https://github.com/quay/clair/commit/b03f1bc3a671a28f914ecf012df5250ebf20df03): Fix failed tests
- [ed9c6ba](https://github.com/quay/clair/commit/ed9c6baf4faecad71828dacabc5e804a7f11252b): Fix pgsql test
- [5bf8365](https://github.com/quay/clair/commit/5bf8365f7b5bf493ec3a3c119538c58abaa29209): Prevent inserting invalid entry to database
- [8aae73f](https://github.com/quay/clair/commit/8aae73f1c8cf4dddb91babde813097789eb876f3): Remove unnecessary logs
- [79af05e](https://github.com/quay/clair/commit/79af05e67d6e6f09bd1913dbfe405ebdbd9a9c59): Fix postgres queries for feature_type
- [073c685](https://github.com/quay/clair/commit/073c685c5b085813a9ffbec20fa3c49332f7ec66): Add proper tests for database migration
- [c6c8fce](https://github.com/quay/clair/commit/c6c8fce39a5c28645b9626bc3774bd6b6aadd427): Add feature_type to initial schema
- [a57d806](https://github.com/quay/clair/commit/a57d80671793d48782f8d3777984e99d02dc1fd9): fix unchecked error
- [0c1b80b](https://github.com/quay/clair/commit/0c1b80b2ed54dcbe227f7233468a5bdc66d4a17e): Implement database queries for detector relationship
- [9c49d9d](https://github.com/quay/clair/commit/9c49d9dc5591d62a86632881af8d7a7f15fbf25e): Move queries to corresponding files
- [dca2d4e](https://github.com/quay/clair/commit/dca2d4e597ba837b6f96f3b3e32e23f6b843f9ab): Add detector to database schema
- [5343309](https://github.com/quay/clair/commit/53433090a39195d9df7c920d2e4d142f89abae31): update the query format
- [aea7455](https://github.com/quay/clair/commit/aea74550e14a0f0121fb21a2bba6bb6882c2050f): Expand layer, namespace column widths
### Pkg
- [c3904c9](https://github.com/quay/clair/commit/c3904c9696bddc20a27db9b4142ae704350bbe3f): Add fsutil to contian file system utility functions
### Pkg/Gitutil
- [c2d887f](https://github.com/quay/clair/commit/c2d887f9e99184af502aca7abbe2044d2929e789): init
### Pkg/Grpcutil
- [c4a3254](https://github.com/quay/clair/commit/c4a32543e85a46a94012cfd03fc199854ccf3b44): use cockroachdb cipher suite
- [1ec2759](https://github.com/quay/clair/commit/1ec2759550d6a6bcae7c7252c8718b783426c653): init
### Pkg/Pagination
- [0565938](https://github.com/quay/clair/commit/05659389569549f445eefac650df260ab4f4f05b): add token type
- [d193b46](https://github.com/quay/clair/commit/d193b46449a64a554c3b54dd637a371769bfe195): init
### Pkg/Timeutil
- [45ecf18](https://github.com/quay/clair/commit/45ecf1881521281f09e437c904e1f211dc36e319): init
### README
- [4db72b8](https://github.com/quay/clair/commit/4db72b8c26a5754d61931c2fd5a6ee1829b9f016): fixed issues address
- [6c3b398](https://github.com/quay/clair/commit/6c3b398607f701ac8f016c804f2b2883c0ca1db9): fix IRC copypasta
### Style
- [bd68578](https://github.com/quay/clair/commit/bd68578b8bdd4488e197ccdf6d9322380c6ae7d0): Fix typo in headline
### Tarutil
- [a3a3707](https://github.com/quay/clair/commit/a3a37072b54840aaebde1cd0bba62b8939dafbdc): convert all filename specs to regexps
- [afd7fe2](https://github.com/quay/clair/commit/afd7fe2554d65040b27291d658af21af8f8ae521): allow file names to be specified by regexp
 - fixes [#456](https://github.com/quay/clair/issues/456)### Travis
- [52ecf35](https://github.com/quay/clair/commit/52ecf35ca67558c1bedefb2259e9af9ad9649f9d): fail if not gofmt -s
- [7492aa3](https://github.com/quay/clair/commit/7492aa31baf5b834088ecb8e8bd6ffd7817e5dd7): fail unformatted protos
### Travis
- [870e812](https://github.com/quay/clair/commit/870e8123769a3dd717bfdcd21473a8e691806653): Drop support for postgres 9.4 postgres 9.4 doesn't support ON CONFLICT, which is required in our implementation.
### Update Documentation
- [1105102](https://github.com/quay/clair/commit/1105102b8449fcf20b8db1b1722eeeeece2f33fa): talk about SUSE support
### Update The Ingress To Use ApiVersion
- [435d053](https://github.com/quay/clair/commit/435d05394a9e7895d8daf2804bbe3668e1666981): networking.k8s.io/v1beta1
### Updater
- [a14b372](https://github.com/quay/clair/commit/a14b372838a72d24110b57c6443d784d6fbe4451): fix stuck updater process
### Updater
- [7084a22](https://github.com/quay/clair/commit/7084a226ae9c5a3aed1248ad3d653100d610146c): extract deduplicate function
- [e16d17d](https://github.com/quay/clair/commit/e16d17dda9d29e8fdc33ef9da6a4a8be0e6b648f): remove original RunUpdate()
- [0d41968](https://github.com/quay/clair/commit/0d41968acdeeb2325bf9573a65fd1d05345ba255): reimplement fetch() with errgroup
- [6c5be7e](https://github.com/quay/clair/commit/6c5be7e1c6856fbae55e77c0a3411e7fe4d61f82): refactor to use errgroup
- [2236b0a](https://github.com/quay/clair/commit/2236b0a5c9a094bde2b7979417b9538cb944e726): Add vulnsrc affected feature type
- [0d18a62](https://github.com/quay/clair/commit/0d18a629cab15d57fb7b00777f1537039b69401b): sleep before continuing the lock loop
 - Fixes [#415](https://github.com/quay/clair/issues/415)### Updater,Pkg/Timeutil
- [f64bd11](https://github.com/quay/clair/commit/f64bd117b2fa946c26a2e3368925f6dae8e4a2d3): minor cleanups
### Upgrade To Golang
- [db5dbbe](https://github.com/quay/clair/commit/db5dbbe4e983a4ac827f5b6597aac780c03124b3): 1.10-alpine
### V3
- [88f5069](https://github.com/quay/clair/commit/88f506918b9cb32ab77e41e0cbbe2f9db6e6b358): Analyze layer content in parallel
- [dd23976](https://github.com/quay/clair/commit/dd239762f63702c1800895ee9b86bdda316830ef): Move services to top of the file
- [9f5d1ea](https://github.com/quay/clair/commit/9f5d1ea4e16793ebd9390673aed34855671b5c24): associate feature and namespace with detector
### Vendor
- [4106322](https://github.com/quay/clair/commit/41063221075cea67636f77f58a9d3e112771b835): Update gopkg.in/yaml.v2 package
- [34d0e51](https://github.com/quay/clair/commit/34d0e516e0792ca2d06299a1262e5676d4145f80): Add golang-set dependency
- [55ecf1e](https://github.com/quay/clair/commit/55ecf1e58aa75346ca6c4d702eb31e02ff32ee0e): regenerate after removing graceful
- [1533dd1](https://github.com/quay/clair/commit/1533dd1d51d4f89febd857897addb6dfb6c161e4): updated vendor dir for grpc v2 api
### Vulnmdsrc
- [ce6b008](https://github.com/quay/clair/commit/ce6b00887b1db3a402b1a02bdebb5bcc23d4add0): update NVD URLs
 - Fixes [#575](https://github.com/quay/clair/issues/575)### Vulnsrc
- [72674ca](https://github.com/quay/clair/commit/72674ca871dd2b0a9afdbd9c6a6b50f49a50b20b): Refactor vulnerability sources to use utility functions
### Vulnsrc Rhel
- [bd7102d](https://github.com/quay/clair/commit/bd7102d96304b02ff09077edc16f5f60bd784c8b): handle "none" CVE impact
### Vulnsrc/Alpine
- [c031f8e](https://github.com/quay/clair/commit/c031f8ea0c793ba0462f2b8a204c15ab3a65f1a5): s/pull/clone
- [4c2be52](https://github.com/quay/clair/commit/4c2be5285e1419844377c11484bd684b45948958): avoid shadowing vars
### Vulnsrc/Ubuntu
- [456af5f](https://github.com/quay/clair/commit/456af5f48c8da8325266209e58cec90f4a3f1f68): use new git-based ubuntu tracker
### Vulnsrc_oracle
- [3503ddb](https://github.com/quay/clair/commit/3503ddb96fe412242b84ec28f36a7ddd787b823f): one vulnerability per CVE
 -  [#495](https://github.com/quay/clair/issues/495) -  [#499](https://github.com/quay/clair/issues/499)### Vulnsrc_rhel
- [c4ffa0c](https://github.com/quay/clair/commit/c4ffa0c370e793546dd51ea25fc98961c2d25970): cve impact
- [a90db71](https://github.com/quay/clair/commit/a90db713a2722a80db33e47343c4a4d417f48a0e): add test
- [8b3338e](https://github.com/quay/clair/commit/8b3338ef56b060e27bc3d81124f52bbded315f1a): minor changes
- [4e4e98f](https://github.com/quay/clair/commit/4e4e98f328309d1c0a470388d198fa37c27e47d5): minor changes
- [ac86a36](https://github.com/quay/clair/commit/ac86a3674094f93b71e8736392b7a4707fa972fe): rhsa_ID by default
- [4ab98cf](https://github.com/quay/clair/commit/4ab98cfe54bedcce7880cc03b1c52d5a91811860): one vulnerability by CVE
 - Fixes [#495](https://github.com/quay/clair/issues/495)### Worker
- [23ccd9b](https://github.com/quay/clair/commit/23ccd9b53ba0a8bcf800fecdbd72d5cbefd2ea60): Fix tests for feature_type
- [f0e21df](https://github.com/quay/clair/commit/f0e21df7830e3f8d00498936d0d292ae6ff6765b): fixed duplicated ns and ns not inherited bug
### Workflows
- [f003924](https://github.com/quay/clair/commit/f0039247e1f4c8a2f97b81896782cb802cdeffd8): add go testing matrix
- [ea5873b](https://github.com/quay/clair/commit/ea5873bc8f57eb4d545e0a25a2da868371196926): fix gh-pages argument
- [cec05a3](https://github.com/quay/clair/commit/cec05a35f71dffb6603a2debb14d5388e80643c7): more workflow automation
- [a19407e](https://github.com/quay/clair/commit/a19407e4fd40585b45ffceb507e24c194db78ccc): fix asset name
- [e1902d4](https://github.com/quay/clair/commit/e1902d4d7c1f7d7fdccc6b339736966d2ece0cf6): proper tag name
- [b2d781c](https://github.com/quay/clair/commit/b2d781c2ed50262f4882e34b2585bf99d80fb15b): bad tar flag
### Pull Requests
- Merge pull request [#955](https://github.com/quay/clair/issues/955) from alecmerdler/openapi-fixes
- Merge pull request [#949](https://github.com/quay/clair/issues/949) from alecmerdler/PROJQUAY-494
- Merge pull request [#936](https://github.com/quay/clair/issues/936) from ldelossa/louis/interface-refactor
- Merge pull request [#933](https://github.com/quay/clair/issues/933) from ldelossa/louis/config-and-make
- Merge pull request [#930](https://github.com/quay/clair/issues/930) from ldelossa/louis/middleware-packaging
- Merge pull request [#929](https://github.com/quay/clair/issues/929) from ldelossa/louis/cc-bump-v0.0.17
- Merge pull request [#924](https://github.com/quay/clair/issues/924) from ldelossa/louis/severity-mapping
- Merge pull request [#903](https://github.com/quay/clair/issues/903) from ldelossa/louis/environment-api
- Merge pull request [#897](https://github.com/quay/clair/issues/897) from ldelossa/louis/state-json
- Merge pull request [#890](https://github.com/quay/clair/issues/890) from ldelossa/louis/remove-healthhandler
- Merge pull request [#877](https://github.com/quay/clair/issues/877) from mtougeron/update-ingress-apiversion
- Merge pull request [#873](https://github.com/quay/clair/issues/873) from coreos/code-owners-update
- Merge pull request [#867](https://github.com/quay/clair/issues/867) from andrewsharon/ubuntu19.10
- Merge pull request [#861](https://github.com/quay/clair/issues/861) from thekbb/fix-broken-link-i-missed
- Merge pull request [#856](https://github.com/quay/clair/issues/856) from thekbb/fix-links
- Merge pull request [#860](https://github.com/quay/clair/issues/860) from jzelinskie/bump-v2-master
- Merge pull request [#851](https://github.com/quay/clair/issues/851) from Allda/log-fix
- Merge pull request [#774](https://github.com/quay/clair/issues/774) from Allda/updater_fix
- Merge pull request [#839](https://github.com/quay/clair/issues/839) from noahklein/nvd-status-error
- Merge pull request [#829](https://github.com/quay/clair/issues/829) from peacocb/peacocb-828-dos-on-ancestry-post
- Merge pull request [#831](https://github.com/quay/clair/issues/831) from MVrachev/patch-1
- Merge pull request [#818](https://github.com/quay/clair/issues/818) from vsamidurai/master
- Merge pull request [#822](https://github.com/quay/clair/issues/822) from imlonghao/bullseye
- Merge pull request [#817](https://github.com/quay/clair/issues/817) from ldelossa/remove-detectors
- Merge pull request [#755](https://github.com/quay/clair/issues/755) from Allda/openshift_cert
- Merge pull request [#808](https://github.com/quay/clair/issues/808) from coreos/add-louis
- Merge pull request [#797](https://github.com/quay/clair/issues/797) from jzelinskie/drone
- Merge pull request [#805](https://github.com/quay/clair/issues/805) from ldelossa/remove-ancestry-copy
- Merge pull request [#794](https://github.com/quay/clair/issues/794) from ldelossa/local-dev-readme-update
- Merge pull request [#793](https://github.com/quay/clair/issues/793) from ldelossa/local-dev-clair-db
- Merge pull request [#788](https://github.com/quay/clair/issues/788) from ldelossa/helm-local-dev
- Merge pull request [#780](https://github.com/quay/clair/issues/780) from jzelinskie/CODEOWNERS
- Merge pull request [#779](https://github.com/quay/clair/issues/779) from jzelinskie/mailing-list
- Merge pull request [#773](https://github.com/quay/clair/issues/773) from flumm/disco
- Merge pull request [#671](https://github.com/quay/clair/issues/671) from ericysim/amazon
- Merge pull request [#766](https://github.com/quay/clair/issues/766) from Allda/lock_timeout
- Merge pull request [#742](https://github.com/quay/clair/issues/742) from bluelabsio/path-templating
- Merge pull request [#739](https://github.com/quay/clair/issues/739) from joelee2012/master
- Merge pull request [#749](https://github.com/quay/clair/issues/749) from cnorthwood/tarutil-glob
- Merge pull request [#741](https://github.com/quay/clair/issues/741) from KeyboardNerd/parallel_download
- Merge pull request [#738](https://github.com/quay/clair/issues/738) from Allda/potentialNamespaceAncestry
- Merge pull request [#721](https://github.com/quay/clair/issues/721) from KeyboardNerd/cache
- Merge pull request [#735](https://github.com/quay/clair/issues/735) from jzelinskie/fix-sweet32
- Merge pull request [#722](https://github.com/quay/clair/issues/722) from Allda/feature_ns
- Merge pull request [#724](https://github.com/quay/clair/issues/724) from KeyboardNerd/ref
- Merge pull request [#728](https://github.com/quay/clair/issues/728) from KeyboardNerd/fix
- Merge pull request [#727](https://github.com/quay/clair/issues/727) from KeyboardNerd/master
- Merge pull request [#725](https://github.com/quay/clair/issues/725) from KeyboardNerd/license_test
- Merge pull request [#723](https://github.com/quay/clair/issues/723) from jzelinskie/lock-tx
- Merge pull request [#720](https://github.com/quay/clair/issues/720) from KeyboardNerd/update_ns
- Merge pull request [#695](https://github.com/quay/clair/issues/695) from saromanov/fix-unchecked-error
- Merge pull request [#712](https://github.com/quay/clair/issues/712) from KeyboardNerd/builder
- Merge pull request [#672](https://github.com/quay/clair/issues/672) from KeyboardNerd/source_package/feature_type
- Merge pull request [#685](https://github.com/quay/clair/issues/685) from jzelinskie/updater-cleanup
- Merge pull request [#701](https://github.com/quay/clair/issues/701) from dustinspecker/patch-1
- Merge pull request [#700](https://github.com/quay/clair/issues/700) from traum-ferienwohnungen/master
- Merge pull request [#680](https://github.com/quay/clair/issues/680) from Allda/slices
- Merge pull request [#687](https://github.com/quay/clair/issues/687) from jzelinskie/suse-config
- Merge pull request [#686](https://github.com/quay/clair/issues/686) from jzelinskie/fix-presentations
- Merge pull request [#679](https://github.com/quay/clair/issues/679) from kubeshield/master
- Merge pull request [#506](https://github.com/quay/clair/issues/506) from openSUSE/reintroduce-suse-opensuse
- Merge pull request [#681](https://github.com/quay/clair/issues/681) from Allda/rhel_severity
- Merge pull request [#667](https://github.com/quay/clair/issues/667) from travelaudience/helm-tolerations
- Merge pull request [#656](https://github.com/quay/clair/issues/656) from glb/elsa_CVEID
- Merge pull request [#650](https://github.com/quay/clair/issues/650) from Katee/add-ubuntu-cosmic
- Merge pull request [#653](https://github.com/quay/clair/issues/653) from brosander/helm-dep
- Merge pull request [#648](https://github.com/quay/clair/issues/648) from HaraldNordgren/go_versions
- Merge pull request [#647](https://github.com/quay/clair/issues/647) from KeyboardNerd/spkg/cvrf
- Merge pull request [#644](https://github.com/quay/clair/issues/644) from KeyboardNerd/bug/git
- Merge pull request [#645](https://github.com/quay/clair/issues/645) from Katee/include-cvssv3
- Merge pull request [#646](https://github.com/quay/clair/issues/646) from KeyboardNerd/spkg/model
- Merge pull request [#640](https://github.com/quay/clair/issues/640) from KeyboardNerd/sourcePackage
- Merge pull request [#639](https://github.com/quay/clair/issues/639) from Katee/update-sha1-to-sha256
- Merge pull request [#638](https://github.com/quay/clair/issues/638) from KeyboardNerd/featureTree
- Merge pull request [#633](https://github.com/quay/clair/issues/633) from coreos/roadmap-1
- Merge pull request [#620](https://github.com/quay/clair/issues/620) from KeyboardNerd/feature/detector
- Merge pull request [#627](https://github.com/quay/clair/issues/627) from haydenhughes/master
- Merge pull request [#624](https://github.com/quay/clair/issues/624) from jzelinskie/probot
- Merge pull request [#621](https://github.com/quay/clair/issues/621) from jzelinskie/gitutil
- Merge pull request [#610](https://github.com/quay/clair/issues/610) from MackJM/wip/master_nvd_httputil
- Merge pull request [#499](https://github.com/quay/clair/issues/499) from yebinama/rhel_CVEID
- Merge pull request [#619](https://github.com/quay/clair/issues/619) from KeyboardNerd/sidac/rm_layer
- Merge pull request [#617](https://github.com/quay/clair/issues/617) from jzelinskie/grpc-refactor
- Merge pull request [#614](https://github.com/quay/clair/issues/614) from KeyboardNerd/sidac/simplify
- Merge pull request [#613](https://github.com/quay/clair/issues/613) from jzelinskie/pkg-pagination
- Merge pull request [#611](https://github.com/quay/clair/issues/611) from jzelinskie/drop-graceful
- Merge pull request [#605](https://github.com/quay/clair/issues/605) from KeyboardNerd/sidchen/feature
- Merge pull request [#606](https://github.com/quay/clair/issues/606) from MackJM/wip/master_httputil
- Merge pull request [#607](https://github.com/quay/clair/issues/607) from jzelinskie/gofmt
- Merge pull request [#604](https://github.com/quay/clair/issues/604) from jzelinskie/nvd-urls
- Merge pull request [#601](https://github.com/quay/clair/issues/601) from KeyboardNerd/sidchen/status
- Merge pull request [#594](https://github.com/quay/clair/issues/594) from reasonerjt/fix-alpine-url
- Merge pull request [#578](https://github.com/quay/clair/issues/578) from naibaf0/fix/helmtemplate/configmap/postgresql
- Merge pull request [#586](https://github.com/quay/clair/issues/586) from robertomlsoares/update-helm-chart
- Merge pull request [#582](https://github.com/quay/clair/issues/582) from brosander/helm-alpine-postgres
- Merge pull request [#571](https://github.com/quay/clair/issues/571) from ErikThoreson/nvdupdates
- Merge pull request [#574](https://github.com/quay/clair/issues/574) from hongli-my/fix-nvd-path
- Merge pull request [#572](https://github.com/quay/clair/issues/572) from arno01/multi-stage
- Merge pull request [#540](https://github.com/quay/clair/issues/540) from jzelinskie/document-proto
- Merge pull request [#569](https://github.com/quay/clair/issues/569) from jzelinskie/ubuntu-git
- Merge pull request [#553](https://github.com/quay/clair/issues/553) from qeqar/master
- Merge pull request [#551](https://github.com/quay/clair/issues/551) from usr42/upgrade_to_1.10-alpine
- Merge pull request [#538](https://github.com/quay/clair/issues/538) from jzelinskie/dockerize-protogen
- Merge pull request [#537](https://github.com/quay/clair/issues/537) from tomer-1/patch-1
- Merge pull request [#532](https://github.com/quay/clair/issues/532) from KeyboardNerd/readme_typo
- Merge pull request [#508](https://github.com/quay/clair/issues/508) from joerayme/bug/436
- Merge pull request [#528](https://github.com/quay/clair/issues/528) from KeyboardNerd/helm_typo
- Merge pull request [#522](https://github.com/quay/clair/issues/522) from vdboor/master
- Merge pull request [#521](https://github.com/quay/clair/issues/521) from yebinama/paclair
- Merge pull request [#518](https://github.com/quay/clair/issues/518) from traum-ferienwohnungen/master
- Merge pull request [#513](https://github.com/quay/clair/issues/513) from leandrocr/patch-1
- Merge pull request [#517](https://github.com/quay/clair/issues/517) from KeyboardNerd/master
- Merge pull request [#505](https://github.com/quay/clair/issues/505) from ericchiang/coc
- Merge pull request [#484](https://github.com/quay/clair/issues/484) from odg0318/master
- Merge pull request [#498](https://github.com/quay/clair/issues/498) from bkochendorfer/contributing-link
- Merge pull request [#482](https://github.com/quay/clair/issues/482) from yfoelling/patch-1
- Merge pull request [#487](https://github.com/quay/clair/issues/487) from ajgreenb/db-connection-backoff
- Merge pull request [#488](https://github.com/quay/clair/issues/488) from caulagi/patch-1
- Merge pull request [#485](https://github.com/quay/clair/issues/485) from yebinama/proxy
- Merge pull request [#481](https://github.com/quay/clair/issues/481) from coreos/stable-release-issue-template
- Merge pull request [#479](https://github.com/quay/clair/issues/479) from yebinama/nvd_vectors
- Merge pull request [#477](https://github.com/quay/clair/issues/477) from bseb/master
- Merge pull request [#469](https://github.com/quay/clair/issues/469) from zamarrowski/master
- Merge pull request [#475](https://github.com/quay/clair/issues/475) from dctrud/clair-singularity
- Merge pull request [#467](https://github.com/quay/clair/issues/467) from grebois/master
- Merge pull request [#465](https://github.com/quay/clair/issues/465) from jzelinskie/github
- Merge pull request [#463](https://github.com/quay/clair/issues/463) from brunomcustodio/fix-ingress
- Merge pull request [#459](https://github.com/quay/clair/issues/459) from arthurlm44/patch-1
- Merge pull request [#458](https://github.com/quay/clair/issues/458) from jzelinskie/linux-vulns
- Merge pull request [#450](https://github.com/quay/clair/issues/450) from jzelinskie/move-token
- Merge pull request [#454](https://github.com/quay/clair/issues/454) from InTheCloudDan/helm-tls-option
- Merge pull request [#455](https://github.com/quay/clair/issues/455) from zmarouf/master
- Merge pull request [#449](https://github.com/quay/clair/issues/449) from jzelinskie/helm
- Merge pull request [#447](https://github.com/quay/clair/issues/447) from KeyboardNerd/ancestry_
- Merge pull request [#448](https://github.com/quay/clair/issues/448) from jzelinskie/woops
- Merge pull request [#444](https://github.com/quay/clair/issues/444) from jzelinskie/docs-refresh
- Merge pull request [#432](https://github.com/quay/clair/issues/432) from KeyboardNerd/ancestry_
- Merge pull request [#442](https://github.com/quay/clair/issues/442) from arminc/add-integration-clari-scanner
- Merge pull request [#433](https://github.com/quay/clair/issues/433) from mssola/portus-integration
- Merge pull request [#408](https://github.com/quay/clair/issues/408) from KeyboardNerd/grpc
- Merge pull request [#423](https://github.com/quay/clair/issues/423) from jzelinskie/sleep-updater
- Merge pull request [#418](https://github.com/quay/clair/issues/418) from KeyboardNerd/multiplens
- Merge pull request [#410](https://github.com/quay/clair/issues/410) from KeyboardNerd/xforward
- Merge pull request [#416](https://github.com/quay/clair/issues/416) from tianon/debian-buster
- Merge pull request [#413](https://github.com/quay/clair/issues/413) from transcedentalia/master
- Merge pull request [#403](https://github.com/quay/clair/issues/403) from KeyboardNerd/multiplens
- Merge pull request [#407](https://github.com/quay/clair/issues/407) from swestcott/kubernetes-config-fix
- Merge pull request [#394](https://github.com/quay/clair/issues/394) from KeyboardNerd/multiplens
- Merge pull request [#382](https://github.com/quay/clair/issues/382) from caipre/patch-1


<a name="v2.1.3"></a>
## [v2.1.3] - 2020-04-20
### Api
- [546fd93](https://github.com/quay/clair/commit/546fd936739d6875b818a9e5ab9b84b3e860794c): use cockroachdb cipher suite
### Api/V1
- [d8560e2](https://github.com/quay/clair/commit/d8560e24c6b111857eadc6b16beb7c52bf9715ec): remove debug statement
### Clair
- [0ef7cee](https://github.com/quay/clair/commit/0ef7cee405354032fd3b22d83663ce5fe70d5e28): remove vendor directory
- [8483a69](https://github.com/quay/clair/commit/8483a696f6dba0add8443d0cbfcd305bdef2c20d): rewrite imports
- [7bc8980](https://github.com/quay/clair/commit/7bc8980e0f1bc6b5ec63ae5230c956fac12eed9e): create module
### Database
- [9a45205](https://github.com/quay/clair/commit/9a452050c85acaa573403edffff1c13921cd460a): add ubuntu cosmic mapping
- [f882e1c](https://github.com/quay/clair/commit/f882e1c2109383fd8a46c33b86c8960d84b5fc90): add ubuntu bionic namespace mapping
### Dockerfile
- [5fed354](https://github.com/quay/clair/commit/5fed3540412d183237400af564f9774e75f4d8b8): bump to Go 1.13
### Ext/Featurens
- [8aeb337](https://github.com/quay/clair/commit/8aeb3374717e643eb7e81f95f0fda61de7042e4d): add support for RHEL8
 - Fixes [#889](https://github.com/quay/clair/issues/889)### Ext/Vulnsrc/Rhel
- [ee4380f](https://github.com/quay/clair/commit/ee4380f51a92b6ec5c29e62829c7d202cb7c3c30): s/Warning/Warningf
### Ext/Vulnsrc/Ubuntu
- [d1cadb4](https://github.com/quay/clair/commit/d1cadb4cdc4784790338aa25e755c79404966791): updated tracker src
 - Fixes [#524](https://github.com/quay/clair/issues/524)### Feat
- [ad6be9c](https://github.com/quay/clair/commit/ad6be9ce0191e70af9672d5aa4b69217c5606082): backport ubuntu 19.10 ([#977](https://github.com/quay/clair/issues/977))
 -  [#977](https://github.com/quay/clair/issues/977)### Featurens
- [e650d58](https://github.com/quay/clair/commit/e650d58583aa48a03f5e9f0ce2621be54cfcee40): Ensure RHEL is correctly identified
 - Fixes [#436](https://github.com/quay/clair/issues/436)### Imgfmt
- [a80ca55](https://github.com/quay/clair/commit/a80ca551cf83e7c3911e68b22f9b05addb74f911): download using http proxy from env
### Rhel
- [5731f5d](https://github.com/quay/clair/commit/5731f5d23c4da2d3953d801867e67b4ef1eab5df): make as much progress as possible on updates
### Use Golang
- [ad98b97](https://github.com/quay/clair/commit/ad98b97a6de6dd4f7cf22c419db316e8676b1bf7): 1.10-alpine with v2.0.2
### Vulnmdsrc
- [5e4c36a](https://github.com/quay/clair/commit/5e4c36aad537b4a14b96214074f97b293261bba7): update NVD URLs
 - Fixes [#575](https://github.com/quay/clair/issues/575)### Pull Requests
- Merge pull request [#898](https://github.com/quay/clair/issues/898) from rpnguyen/ubi8-backport-release-2.0
- Merge pull request [#895](https://github.com/quay/clair/issues/895) from andrewsharon/release-2.0
- Merge pull request [#887](https://github.com/quay/clair/issues/887) from ldelossa/louis/rhel-import-fix
- Merge pull request [#875](https://github.com/quay/clair/issues/875) from quay/v2-module
- Merge pull request [#876](https://github.com/quay/clair/issues/876) from reasonerjt/nvd-json-2.0
- Merge pull request [#859](https://github.com/quay/clair/issues/859) from jzelinskie/v2-bump-go
- Merge pull request [#846](https://github.com/quay/clair/issues/846) from ErikThoreson/v2.0.9-nvdfix
- Merge pull request [#840](https://github.com/quay/clair/issues/840) from glb/bugfix-231-release-2.0
- Merge pull request [#823](https://github.com/quay/clair/issues/823) from imlonghao/release-2.0-bullseye
- Merge pull request [#769](https://github.com/quay/clair/issues/769) from roxspring/backport/[gh-630](https://github.com/quay/clair/issues/630)-dumb-init
- Merge pull request [#776](https://github.com/quay/clair/issues/776) from flumm/release-2.0-disco
- Merge pull request [#736](https://github.com/quay/clair/issues/736) from jzelinskie/fix-sweet32-v2
- Merge pull request [#615](https://github.com/quay/clair/issues/615) from reasonerjt/updater-loop-2.0
- Merge pull request [#603](https://github.com/quay/clair/issues/603) from MackJM/httpclient
- Merge pull request [#599](https://github.com/quay/clair/issues/599) from reasonerjt/fix-alpine-url-2.0
- Merge pull request [#530](https://github.com/quay/clair/issues/530) from meringu/patch-1
- Merge pull request [#568](https://github.com/quay/clair/issues/568) from MackJM/release-2.0
- Merge pull request [#562](https://github.com/quay/clair/issues/562) from ninjaMog/ubuntu-tracker-update
- Merge pull request [#565](https://github.com/quay/clair/issues/565) from ninjaMog/nvd-endpoint-update
- Merge pull request [#554](https://github.com/quay/clair/issues/554) from usr42/release-2.0_go1.10
- Merge pull request [#531](https://github.com/quay/clair/issues/531) from bison/oracle-regex
- Merge pull request [#423](https://github.com/quay/clair/issues/423) from jzelinskie/sleep-updater
- Merge pull request [#407](https://github.com/quay/clair/issues/407) from swestcott/kubernetes-config-fix
- Merge pull request [#413](https://github.com/quay/clair/issues/413) from transcedentalia/master
- Merge pull request [#416](https://github.com/quay/clair/issues/416) from tianon/debian-buster


<a name="v4.0.0-alpha.3"></a>
## [v4.0.0-alpha.3] - 2020-04-14
### Clair
- [fa95f5d](https://github.com/quay/clair/commit/fa95f5d80c86f3e916661156f99dac6fcc91a3bb): bump claircore version
### Clairctl
- [2e68178](https://github.com/quay/clair/commit/2e6817881eed93af469abd7e16839961aa812469): remove log.Lmsgprefix
- [0282f68](https://github.com/quay/clair/commit/0282f68bf381a5b0a592079819e38b3d88296f92): report command
### Client
- [1ba6891](https://github.com/quay/clair/commit/1ba68911163afb001cd89cf84862506f008edcf4): add differ and refactor client
### Config
- [b2666e5](https://github.com/quay/clair/commit/b2666e57202d7c690a40d7c86975c13e0b3db56e): set a canonical default port
### Dockerfile
- [33da12a](https://github.com/quay/clair/commit/33da12a3bb9a28fdbcc6302caa4212d38a2acbbb): run as unprivledged user by default
### Documentation
- [fe324a5](https://github.com/quay/clair/commit/fe324a58e6be8c36da74afcd5487d0da4a547d5b): start writing v4-specific docs
### Httptransport
- [e783062](https://github.com/quay/clair/commit/e783062b41af06eed250d289a2dfa43a4b6aeb25): wire in update endpoints
- [9cd6cab](https://github.com/quay/clair/commit/9cd6cabf62b60bd47bd2f6546cd5a806f1d79ad3): report write errors via trailer
### Workflows
- [f003924](https://github.com/quay/clair/commit/f0039247e1f4c8a2f97b81896782cb802cdeffd8): add go testing matrix
- [ea5873b](https://github.com/quay/clair/commit/ea5873bc8f57eb4d545e0a25a2da868371196926): fix gh-pages argument
- [cec05a3](https://github.com/quay/clair/commit/cec05a35f71dffb6603a2debb14d5388e80643c7): more workflow automation
- [a19407e](https://github.com/quay/clair/commit/a19407e4fd40585b45ffceb507e24c194db78ccc): fix asset name
### Pull Requests
- Merge pull request [#955](https://github.com/quay/clair/issues/955) from alecmerdler/openapi-fixes


<a name="v4.0.0-alpha.2"></a>
## [v4.0.0-alpha.2] - 2020-03-26
### *
- [74efdf6](https://github.com/quay/clair/commit/74efdf6b51e3e625ca9f122e7aa88e88f4708a68): update roadmap
 - Fixes [#626](https://github.com/quay/clair/issues/626)- [ce15f73](https://github.com/quay/clair/commit/ce15f73501b758b3d24e06753ce62123d0a36920): gofmt -s
- [5caa821](https://github.com/quay/clair/commit/5caa821c80a4efa2986728d6f223552b44f6ce15): remove bzr dependency
- [033cae7](https://github.com/quay/clair/commit/033cae7d358b2f7b866da7d9be3367d902cdf035): regenerate bill of materials
- [1f5bc26](https://github.com/quay/clair/commit/1f5bc26320bc58676d88c096404a8503dca7a4d8): rename example config
### .Github
- [9b1f205](https://github.com/quay/clair/commit/9b1f2058338b8aeaa5441091b4920731235f1353): add stale and issue template enforcement
### API
- [0151dba](https://github.com/quay/clair/commit/0151dbaef81cae54aa95dd8abf36d58414de2b26): change api port to api addr, rename RunV2 to Run.
 - Fixes [#446](https://github.com/quay/clair/issues/446)- [a378cb0](https://github.com/quay/clair/commit/a378cb070cb9ec56f363ec08adb8e023bfb3994e): drop v1 api, changed v2 api for Clair v3.
### All
- [fbbffcd](https://github.com/quay/clair/commit/fbbffcd2c2a34d8a6128a06a399234b444c74d09): add opentelemetry hooks
### Api
- [69c0c84](https://github.com/quay/clair/commit/69c0c84348c74749cd1d12ee4e4959991621a59d): Rename detector type to DType
- [48427e9](https://github.com/quay/clair/commit/48427e9b8808f86929ffb905952395c91644f04e): Add detectors for RPC
- [dc6be5d](https://github.com/quay/clair/commit/dc6be5d1b073d87b2405d84d33f5bb5f6ced490e): remove handleShutdown func
- [30644fc](https://github.com/quay/clair/commit/30644fcc01df7748d8e2ae15c427f01702dd4e90): remove dependency on graceful
- [58022d9](https://github.com/quay/clair/commit/58022d97e3ec7194e89522c9adb866a85c704378): renamed V2 API to V3 API for consistency.
- [c6f0eaa](https://github.com/quay/clair/commit/c6f0eaa3c82197f15371b4d2c8af686d8a7a569f): fix remote addr shows reverse proxy addr problem
- [a4edf38](https://github.com/quay/clair/commit/a4edf385663b2e412e1fd64f7d45e1ee01749798): v2 api with gRPC and gRPC-gateway
 - Fixes [#98](https://github.com/quay/clair/issues/98)### Api,Database
- [a75b8ac](https://github.com/quay/clair/commit/a75b8ac7ffe3ccd7ff9c4718e547c6c5103e9747): updated version_format documentation.
 - Fixes [#514](https://github.com/quay/clair/issues/514)### Api/V3
- [32b11e5](https://github.com/quay/clair/commit/32b11e54eb287ed0d686ba72fe413b773b748a38): Add feature type to API feature
- [f550dd1](https://github.com/quay/clair/commit/f550dd16a01edc17de0e3c658c5f7bc25639a0a1): remove dependency on google empty message
- [d7a751e](https://github.com/quay/clair/commit/d7a751e0d4298442883fde30ee37c529b2bb3719): prototool format
### Api/V3/Clairpb
- [6b9f668](https://github.com/quay/clair/commit/6b9f668ea0b657526b35008f8efd9c8f0a46df9b): document and regenerate protos
- [ec5014f](https://github.com/quay/clair/commit/ec5014f8a13605458faf1894bb905f2123ded0a7): regen protobufs
- [389b6e9](https://github.com/quay/clair/commit/389b6e992790f6e28b77ca5979c0589e43dbe40a): generate protobufs in docker
### CODEOWNERS
- [f20a72c](https://github.com/quay/clair/commit/f20a72c34ef80b4c1dee7b9984aa713f82e6c342): add Louis
- [abf6e74](https://github.com/quay/clair/commit/abf6e74790294bb765a68765afa9d8e73c3fab22): init
### Clair
- [42b1ba9](https://github.com/quay/clair/commit/42b1ba9f91f9174397280152eca5a0096342019e): use Etag header to communicate indexer state change
- [fd5993f](https://github.com/quay/clair/commit/fd5993f9765cc23355e5895105a15b71e5eb3156): add "mode" argument
- [4091329](https://github.com/quay/clair/commit/409132958e0538046e3481d3197e192316b06d91): change version information
- [8cbddd1](https://github.com/quay/clair/commit/8cbddd187e7065315417ca2f86a5e261f3d92651): better introspection server defaults
- [c097454](https://github.com/quay/clair/commit/c097454c182daa68427918d0ba2fe24bbdf6ed71): logging and introspection setup
- [a003aa4](https://github.com/quay/clair/commit/a003aa414ead82a32b24a977e301e5697718ec43): add configuration for introspection
- [d9db7c1](https://github.com/quay/clair/commit/d9db7c153ce80d3d47bbb342bd6ef873bc2954b4): use "Updaters" config option
- [48daeae](https://github.com/quay/clair/commit/48daeaeacc5a1444a07cc6ddc20b4b800d8b43be): fix header casing
- [fb28e56](https://github.com/quay/clair/commit/fb28e569da21f847c7bbc2f97807485ea007e698): remove os.Exit call on clean shutdown
- [8039e1c](https://github.com/quay/clair/commit/8039e1c95f56353e47aaa5ed66b80244ac2d2cad): add authorization checking
- [1b41336](https://github.com/quay/clair/commit/1b41336265126c23b152d18c28ea6e0fd3d6baf8): update claircore to 0.0.14
- [791610f](https://github.com/quay/clair/commit/791610f1c893fc76d6fcf350a7383a2479aa723a): remove goautoneg
- [7b6ef7d](https://github.com/quay/clair/commit/7b6ef7da8c125111ec37fe61206dce1ee25408ec): reset writers when pulled from pool
- [ad73d74](https://github.com/quay/clair/commit/ad73d747fcc6c674752eaf5ae7ccdcb6fa4daead): remove vendor directory
- [00eff59](https://github.com/quay/clair/commit/00eff59af580893d3e045333fa095d3507a528f1): rewrite imports
- [1f2ceeb](https://github.com/quay/clair/commit/1f2ceeb8f7fcf9e8ce94206f76a8b610b84424ca): create module
- [c6497dd](https://github.com/quay/clair/commit/c6497dda0a95a3309dc649761243250634a31d40): Fix namespace update logic
- [465687f](https://github.com/quay/clair/commit/465687fa94b4e9fe00e0ba1190989d0d454c14ab): Add more logging on ancestry cache hit
- [5b23764](https://github.com/quay/clair/commit/5b2376498bbc0ea0a893754887defce4daa59daa): Use builder pattern for constructing ancestry
- [0283240](https://github.com/quay/clair/commit/028324014ba3b7111e4e4533d6a8d4d99bb1fd72): Implement worker detector support
### Clair Logic, Extensions
- [fb32dcf](https://github.com/quay/clair/commit/fb32dcfa58077dadd8bfbf338c4aa342d5e9ef85): updated mock tests, extensions, basic logic
### Clairctl
- [f1c4798](https://github.com/quay/clair/commit/f1c4798bb10292fe1f14d71691ab33d4ea5a2ae9): start on clair cli tool
### Cmd/Clair
- [b20482e](https://github.com/quay/clair/commit/b20482e0aebcf2cc67f61e8ff821ddcdffc53ac7): document constants
### Config
- [4f23269](https://github.com/quay/clair/commit/4f232698b0178ef9d1a3cde01b6ff40e47659cfa): add updaters and tracing options
- [162e8cd](https://github.com/quay/clair/commit/162e8cdafc66be28b021f83da736a2b612ddda99): enable suse updater
- [0609ed9](https://github.com/quay/clair/commit/0609ed964b0673806462a24147e6028da85d8a38): removed worker config
### Contrib
- [76b9f8e](https://github.com/quay/clair/commit/76b9f8ea05b110d1ff659964fc9126824ec28b17): replace old k8s manifests with helm
- [ac1cdd0](https://github.com/quay/clair/commit/ac1cdd03c9e31ddaea627e076704f38a0d4719fb): move grafana and compose here
### Contrib/Helm/Clair
- [13be17a](https://github.com/quay/clair/commit/13be17a69082d30996d53d3087b7265007bae555): fix the ingress template
### Convert
- [f2ce832](https://github.com/quay/clair/commit/f2ce8325b975a15c977654d3be1084ad1e890bf3): return nil when detector is empty
### Database
- [506698a](https://github.com/quay/clair/commit/506698a4246e24bb3a72bd626d95bd47dc38beb8): add mapping for Ubuntu Eoan (19.10)
- [1ddc053](https://github.com/quay/clair/commit/1ddc0532e4be8dac02e171b986da51deaffbb636): Handle FindAncestryAndRollback datastore.Begin() error
 - Fixes [#828](https://github.com/quay/clair/issues/828)- [6617f56](https://github.com/quay/clair/commit/6617f560cc9ce90eece08aca29841827c72ca5c2): Rename affected type to feature type (for Amazon Linux updater)
- [3fafb73](https://github.com/quay/clair/commit/3fafb73c4fe0e9fbc03d1c5657b57ba0ca04c000): Split models.go into different files each contains one model
- [1b9ed99](https://github.com/quay/clair/commit/1b9ed99646e492a27e982ae34dea7c6fc7273c52): Move db logic to dbutil
- [961c7d4](https://github.com/quay/clair/commit/961c7d4680c58e3b01eedb4361a3fa57a1f9a904): add test for lock expiration
- [a4e7873](https://github.com/quay/clair/commit/a4e7873d1432b9b593f2e9dc44a02f2badea9002): make locks SOI & add Extend method
- [5fa1ac8](https://github.com/quay/clair/commit/5fa1ac89b9946f2e32ac666080b4f78ad1f9bbfa): Add StorageError type
- [f616753](https://github.com/quay/clair/commit/f61675355e7a296989e778f37257e6e416e6f208): Update feature model Remove source name/version fields Add Type field to indicate if it's binary package or source package
- [7dd989c](https://github.com/quay/clair/commit/7dd989c0f21bc5c4cb390f575dca9973829ef9ce): Rename affected Type to feature type
- [00eed77](https://github.com/quay/clair/commit/00eed77b451b8913771feef7a40067dd246d7872): Add feature_type database model
- [dd91597](https://github.com/quay/clair/commit/dd91597f19dae90e8b671d2c80004f0a28dc177c): remove FindLock from mock
- [399deab](https://github.com/quay/clair/commit/399deab1005b7c3541ad0dacb52bd7961b5167cc): remove FindLock()
- [300bb52](https://github.com/quay/clair/commit/300bb52696036dce96ee360f4431837e6ee452a2): add FindLock dbutil
- [4fbeb9c](https://github.com/quay/clair/commit/4fbeb9ced594b17aeee3e022f87ed7345376f232): add (Acquire|Release)Lock dbutils
- [6c682da](https://github.com/quay/clair/commit/6c682da3e138e0a7d09dadae7040d8cebba88e2b): add mapping for Ubuntu Cosmic (18.10)
- [a3f7387](https://github.com/quay/clair/commit/a3f7387ff146226f31a03906591cbb0d0e64cb44): Add FindKeyValue function wrapper
- [00fadfc](https://github.com/quay/clair/commit/00fadfc3e3da8c25b6c0c3f13d48017173a45a93): Add affected feature type
- [f759dd5](https://github.com/quay/clair/commit/f759dd54c028e8b39fd1e21c8c70ebda567aa7cd): Replace Parent Feature with source metadata
- [3fe894c](https://github.com/quay/clair/commit/3fe894c5ad7b33223be4a6d52bc0d88fc0fd3a18): Add parent feature pointer to Feature struct
- [a3e9b5b](https://github.com/quay/clair/commit/a3e9b5b55d13921b61e2f92a1ade9392b6e7d7a0): rename utility functions with commit/rollback
- [e657d26](https://github.com/quay/clair/commit/e657d26313b1b91fe4dab17298597119dc919cd2): move dbutil and testutil to database from pkg
- [db2db8b](https://github.com/quay/clair/commit/db2db8bbe8a17e10c9fb365196f88d552e70e91d): Update database model and interface for detectors
- [e160616](https://github.com/quay/clair/commit/e160616723643beff99363b7b385fd4b8ce6802a): Use LayerWithContent as Layer
- [ff93039](https://github.com/quay/clair/commit/ff9303905beb2e2f28d2a33e3fc232cd846b5963): changed Notification interface name
- [a5c6400](https://github.com/quay/clair/commit/a5c6400065a873f6ae14d50b73550dc07239d7bf): postgres implementation with tests.
### Database/Pgsql
- [4491bed](https://github.com/quay/clair/commit/4491bedf2e284007fa7f527bf264dc98c937d820): move token lib
### Datastore
- [57b146d](https://github.com/quay/clair/commit/57b146d0d808a29db9f299778fb5527cd0974b06): updated for Clair V3, decoupled interfaces and models
### Dockerfile
- [2ca92d0](https://github.com/quay/clair/commit/2ca92d00754b1d1859e9d6f3169d67d6b96d6bee): bump Go to 1.13
### Dockerfile
- [e56b95a](https://github.com/quay/clair/commit/e56b95aca0085067f91f90e3b32dab9d04e7fb48): use environment variables
- [33b3224](https://github.com/quay/clair/commit/33b3224df13b9c2aa8b0281f120997abce82eaf9): update for clair v4
### Docs
- [49b5621](https://github.com/quay/clair/commit/49b5621d738978c94e8d311775bba48a1daafc7e): fix typo in running-clair
- [9ee2ff4](https://github.com/quay/clair/commit/9ee2ff4877db15a5ad8ae24afcb8f02f0e8289cf): add troubleshooting about kernel packages
- [3f91bd2](https://github.com/quay/clair/commit/3f91bd2a9bc40bd7b6f4e5a5a8a533de383f3554): turn README into full articles
### Documentation
- [c1a58bf](https://github.com/quay/clair/commit/c1a58bf9224bbcd7e0f02ea4065650d220654f29): add new 3rd party tool
### Documentation
- [3e6896c](https://github.com/quay/clair/commit/3e6896c6a4e5cdd04d91927d762b332b62e1d4fe): fix links to presentations
 - Closes [#661](https://github.com/quay/clair/issues/661) - Closes [#665](https://github.com/quay/clair/issues/665) - Closes [#560](https://github.com/quay/clair/issues/560)### Driver
- [5c58575](https://github.com/quay/clair/commit/5c5857548d43fa866d46a4c98309b2dfa88be418): Add proxy support
### Drone
- [0fd9cd3](https://github.com/quay/clair/commit/0fd9cd3b59bd42ef0e508f0f415028a0ee8fa44f): remove broken drone CI
- [352f738](https://github.com/quay/clair/commit/352f73834e7bdef31dc5e3a715133f5c47947764): init
### Ext
- [25078ac](https://github.com/quay/clair/commit/25078ac838920e4010ecdbe4546af0d4b502dabd): add CleanAll() utility functions
- [081ae34](https://github.com/quay/clair/commit/081ae34af146365146cf4548a8a0afa293e15695): remove duplicate vectorValuesToLetters definition
- [4f0da12](https://github.com/quay/clair/commit/4f0da12b123ec543a58936c0f7226254e411cc00): pass through CVSSv3 impact and exploitability score
- [8efc3e4](https://github.com/quay/clair/commit/8efc3e40382287e88714fdcf634a79e6347b6157): remove unneeded use of init()
- [699d114](https://github.com/quay/clair/commit/699d1143e5ab2a673d0f83249f3268cfebaf3e57): fixup incorrect copyright year
- [b81e445](https://github.com/quay/clair/commit/b81e4454fbb7f3dcec4a2dd6064820bf0c6321f2): Parse CVSSv3 data from JSON NVD feed
- [14277a8](https://github.com/quay/clair/commit/14277a8f5d95799bb651c194785dd04e75a08ee1): Add JSON NVD parsing tests
- [aab46f5](https://github.com/quay/clair/commit/aab46f5658cf5a75262945033cb41d93af5f2131): Parse NVD JSON feed instead of XML
- [8d5a013](https://github.com/quay/clair/commit/8d5a0131c48d0812d1dd53b1af8e24ae4e51c4ba): Use SHA256 instead of SHA1 for fingerprinting
- [53bf19a](https://github.com/quay/clair/commit/53bf19aecfcccb367bc359a2dd6d7320fa4e4855): Lister and Detector returns detector info with detected content
### Ext/Featurefmt
- [1c40e7d](https://github.com/quay/clair/commit/1c40e7d01697f5680408f138e6974266c6530cb1): Refactor featurefmt testing code
### Ext/Featurefmt/Apk
- [2cc61f9](https://github.com/quay/clair/commit/2cc61f9fc0edc42d2c0fda71471208e3faba507d): Extract origin package information from database
### Ext/Featurefmt/Dpkg
- [4ac0466](https://github.com/quay/clair/commit/4ac046642ffea9fb60af455b9d22d19cd4408f32): Extract source package metadata
### Ext/Featurefmt/Rpm
- [a057e4a](https://github.com/quay/clair/commit/a057e4a943dc1a2dc1898b67435b05417725402e): Extract source package from rpm database
### Feature
- [90f5592](https://github.com/quay/clair/commit/90f5592095f74e9704193f4362c494571667b326): replace arrays with slices
### Featurefmt
- [34c2d96](https://github.com/quay/clair/commit/34c2d96b3685a927749536017add6538578fb2df): Extract PotentialNamespace
- [0e0d8b3](https://github.com/quay/clair/commit/0e0d8b38bba4c62552c98ad5b98242ddd2c3464b): Extract source packages and binary packages The featurefmt now extracts both binary packages and source packages from the package manager infos.
- [9561d62](https://github.com/quay/clair/commit/9561d623c29394dddca0823721d7d3622b3dec65): use namespace's versionfmt to specify listers
### Featurens
- [947a8aa](https://github.com/quay/clair/commit/947a8aa00c6f72a20e7fca63993dafaf3185fdc4): Ensure RHEL is correctly identified
 - Fixes [#436](https://github.com/quay/clair/issues/436)- [50437f3](https://github.com/quay/clair/commit/50437f32a1d7d609cfd5e6eb3f0bbf180099fc05): fix detecting duplicated namespaces problem
- [75d5d40](https://github.com/quay/clair/commit/75d5d40d796f4233a58c16443614933c8b326d49): added multiple namespace testing for namespace detector
### Fix
- [4e49aaf](https://github.com/quay/clair/commit/4e49aaf34647ab636595c1ba631efa0cea56ceac): lock updater - return correct bool value
### Github
- [6a42aba](https://github.com/quay/clair/commit/6a42aba3aa7c73627fd73da3d57dd233de1184e8): add mailing list!
- [c7a67ed](https://github.com/quay/clair/commit/c7a67edf5d8957ff05391770d6800e9e83b6b0a9): add issue template stable release notice
- [f6cac47](https://github.com/quay/clair/commit/f6cac4733a7545736d5875f0b36324481098d471): add issue template
- [24ca12b](https://github.com/quay/clair/commit/24ca12bdecfcbc2d7797a01dcde87fea44dad7c8): move CONTRIBUTING to github dir
### Gitutil
- [11b67e6](https://github.com/quay/clair/commit/11b67e612c3703af63a4c63364ea60445077a2a7): Fix git pull on non-git repository directory
 - Fixes [#641](https://github.com/quay/clair/issues/641)### Glide
- [165c397](https://github.com/quay/clair/commit/165c397f169409dfce9b41459d5845e774c8ef81): add errgroup and regenerate vendor
### Go.Mod
- [ad58dd9](https://github.com/quay/clair/commit/ad58dd9758726e488b5c60a47b602f1492de7204): update to latest claircore
### HELM
- [81430ff](https://github.com/quay/clair/commit/81430ffbb252990ebfd74b0bba284c7564b69dae): also add option for nodeSelector
- [6a94d8c](https://github.com/quay/clair/commit/6a94d8ccd267cc428dd2161bb1e5b71dd3cd244f): add option for tolerations
### Helm
- [690d26e](https://github.com/quay/clair/commit/690d26edbac2605b19900549b70d74fa47bdfef9): change postgresql connection string format in configmap template
 - Fixes [#561](https://github.com/quay/clair/issues/561)- [7a06a7a](https://github.com/quay/clair/commit/7a06a7a2b4a68c2567a5bcc41c497fdb9d8d2c15): Fixed a typo in maintainers field.
### Helm
- [710c655](https://github.com/quay/clair/commit/710c65530f4524693e6a863075b4d3760901a3bc): allow for ingress path configuration in values.yml
### Helm Chart
- [bc6f37f](https://github.com/quay/clair/commit/bc6f37f1ae0df5a7c01184ef1483a889e82e86ba): Use Secret for config file. Fix some minor issues
 - Fixes [#581](https://github.com/quay/clair/issues/581)### Imagefmt
- [891ce16](https://github.com/quay/clair/commit/891ce1697d0e53e253001d0ae7620f31b886618c): Move layer blob download logic to blob.go
### Indexer
- [500355b](https://github.com/quay/clair/commit/500355b53c213193147e653b147afc3036ea2125): add basic latency summary
- [8953724](https://github.com/quay/clair/commit/8953724bab392fa3897c2fae62b5df6e9567047c): QoL changes to headers
- [741fc2c](https://github.com/quay/clair/commit/741fc2c4bacb7e5651b05b298257a41ec7558858): HTTP correctness changes
- [10d2f54](https://github.com/quay/clair/commit/10d2f5472efc414846b56edf9d77a69246ea06b2): rename index endpoint
- [ac0a0d4](https://github.com/quay/clair/commit/ac0a0d49424f1f19b5044ea84a245e3139b5adb3): add Accept-Encoding aware middleware
- [3a9ca8e](https://github.com/quay/clair/commit/3a9ca8e57a041bdd78d5e37a904a1ff5942befd8): add State method
### Layer
- [015a79f](https://github.com/quay/clair/commit/015a79fd5a077a3e8340f8cef8610512f53ef053): replace arrays with slices
### Mapping
- [07a08a4](https://github.com/quay/clair/commit/07a08a4f53cab155814eadde44a847e2389b5bcc): add ubuntu mapping
 - Fixes [#552](https://github.com/quay/clair/issues/552)### Matcher
- [15c098c](https://github.com/quay/clair/commit/15c098c48cac6e87b82a4af4b5914aef0ab83310): add basic latency summary
- [0017946](https://github.com/quay/clair/commit/0017946470397c252b1934d1637fe7b1d01fe280): return OK instead of Created
### Nvd
- [e953a25](https://github.com/quay/clair/commit/e953a259b008042d733a4c0aadc9b85d1bedf251): fix the name of a field
### Openapi
- [1949ec3](https://github.com/quay/clair/commit/1949ec3a22a5d2dd5cc30a5fccb99c49a657677a): lint and update Layer
### PgSQL
- [57a4f97](https://github.com/quay/clair/commit/57a4f977803e5eb0d5ddb23e6d54e8490efe89c9): fixed invalidating vulnerability cache query.
### Pgsql
- [0731df9](https://github.com/quay/clair/commit/0731df972c5270d2540411cc2ae1b4f3c9b36dc6): Remove unused test code
- [dfa07f6](https://github.com/quay/clair/commit/dfa07f6d860c59ba2b2cc4909d38f650e9d3969b): Move notification to its module
- [921acb2](https://github.com/quay/clair/commit/921acb26fe875ed18c95b2f62a73fa3e1a8aa355): Split vulnerability.go to files in vulnerability module
- [7cc83cc](https://github.com/quay/clair/commit/7cc83ccbc5b4e34762d10343c2bc989a14fddebc): Split ancestry.go to files in ancestry module
- [497b79a](https://github.com/quay/clair/commit/497b79a293ce9d07f34ffd8ea51264c8ae6bd84c): Add test for migrations
- [ea418cf](https://github.com/quay/clair/commit/ea418cffd474252d9a59881677daffbdaa507768): Split layer.go to files in layer module
- [176c69e](https://github.com/quay/clair/commit/176c69e59dfbd4b39d520005b712858dff502e45): Move namespace to its module
- [98e81ff](https://github.com/quay/clair/commit/98e81ff5f1230f67c3a73055f694a423763062a7): Move keyvalue to keyvalue module
- [ba50d7c](https://github.com/quay/clair/commit/ba50d7c62648471e6e7cf74afe14e9c3268a3a98): Move lock to lock module
- [0b32b36](https://github.com/quay/clair/commit/0b32b36cf7168eef2c005a3d7ec9c3a5996d910b): Move detector to pgsql/detector module
- [c50a233](https://github.com/quay/clair/commit/c50a2339b79c2b5af8552ab6ae4d0e9441df57ac): Split feature.go to table based files in feature module
- [43f3ea8](https://github.com/quay/clair/commit/43f3ea87d86097c81951faf96c000b05445d0947): Move batch queries to corresponding modules
- [a330506](https://github.com/quay/clair/commit/a33050637b4b28f947eb8256cd48ee35d2fe5bfe): Move extra logic in pgsql.go to util folder
- [8bebea3](https://github.com/quay/clair/commit/8bebea3643e294bb11a1766ec450b1e518b0003b): Split testutil.go into multiple files
- [b03f1bc](https://github.com/quay/clair/commit/b03f1bc3a671a28f914ecf012df5250ebf20df03): Fix failed tests
- [ed9c6ba](https://github.com/quay/clair/commit/ed9c6baf4faecad71828dacabc5e804a7f11252b): Fix pgsql test
- [5bf8365](https://github.com/quay/clair/commit/5bf8365f7b5bf493ec3a3c119538c58abaa29209): Prevent inserting invalid entry to database
- [8aae73f](https://github.com/quay/clair/commit/8aae73f1c8cf4dddb91babde813097789eb876f3): Remove unnecessary logs
- [79af05e](https://github.com/quay/clair/commit/79af05e67d6e6f09bd1913dbfe405ebdbd9a9c59): Fix postgres queries for feature_type
- [073c685](https://github.com/quay/clair/commit/073c685c5b085813a9ffbec20fa3c49332f7ec66): Add proper tests for database migration
- [c6c8fce](https://github.com/quay/clair/commit/c6c8fce39a5c28645b9626bc3774bd6b6aadd427): Add feature_type to initial schema
- [a57d806](https://github.com/quay/clair/commit/a57d80671793d48782f8d3777984e99d02dc1fd9): fix unchecked error
- [0c1b80b](https://github.com/quay/clair/commit/0c1b80b2ed54dcbe227f7233468a5bdc66d4a17e): Implement database queries for detector relationship
- [9c49d9d](https://github.com/quay/clair/commit/9c49d9dc5591d62a86632881af8d7a7f15fbf25e): Move queries to corresponding files
- [dca2d4e](https://github.com/quay/clair/commit/dca2d4e597ba837b6f96f3b3e32e23f6b843f9ab): Add detector to database schema
- [5343309](https://github.com/quay/clair/commit/53433090a39195d9df7c920d2e4d142f89abae31): update the query format
- [aea7455](https://github.com/quay/clair/commit/aea74550e14a0f0121fb21a2bba6bb6882c2050f): Expand layer, namespace column widths
### Pkg
- [c3904c9](https://github.com/quay/clair/commit/c3904c9696bddc20a27db9b4142ae704350bbe3f): Add fsutil to contian file system utility functions
### Pkg/Gitutil
- [c2d887f](https://github.com/quay/clair/commit/c2d887f9e99184af502aca7abbe2044d2929e789): init
### Pkg/Grpcutil
- [c4a3254](https://github.com/quay/clair/commit/c4a32543e85a46a94012cfd03fc199854ccf3b44): use cockroachdb cipher suite
- [1ec2759](https://github.com/quay/clair/commit/1ec2759550d6a6bcae7c7252c8718b783426c653): init
### Pkg/Pagination
- [0565938](https://github.com/quay/clair/commit/05659389569549f445eefac650df260ab4f4f05b): add token type
- [d193b46](https://github.com/quay/clair/commit/d193b46449a64a554c3b54dd637a371769bfe195): init
### Pkg/Timeutil
- [45ecf18](https://github.com/quay/clair/commit/45ecf1881521281f09e437c904e1f211dc36e319): init
### README
- [4db72b8](https://github.com/quay/clair/commit/4db72b8c26a5754d61931c2fd5a6ee1829b9f016): fixed issues address
- [6c3b398](https://github.com/quay/clair/commit/6c3b398607f701ac8f016c804f2b2883c0ca1db9): fix IRC copypasta
### Style
- [bd68578](https://github.com/quay/clair/commit/bd68578b8bdd4488e197ccdf6d9322380c6ae7d0): Fix typo in headline
### Tarutil
- [a3a3707](https://github.com/quay/clair/commit/a3a37072b54840aaebde1cd0bba62b8939dafbdc): convert all filename specs to regexps
- [afd7fe2](https://github.com/quay/clair/commit/afd7fe2554d65040b27291d658af21af8f8ae521): allow file names to be specified by regexp
 - fixes [#456](https://github.com/quay/clair/issues/456)### Travis
- [870e812](https://github.com/quay/clair/commit/870e8123769a3dd717bfdcd21473a8e691806653): Drop support for postgres 9.4 postgres 9.4 doesn't support ON CONFLICT, which is required in our implementation.
### Travis
- [52ecf35](https://github.com/quay/clair/commit/52ecf35ca67558c1bedefb2259e9af9ad9649f9d): fail if not gofmt -s
- [7492aa3](https://github.com/quay/clair/commit/7492aa31baf5b834088ecb8e8bd6ffd7817e5dd7): fail unformatted protos
### Update Documentation
- [1105102](https://github.com/quay/clair/commit/1105102b8449fcf20b8db1b1722eeeeece2f33fa): talk about SUSE support
### Update The Ingress To Use ApiVersion
- [435d053](https://github.com/quay/clair/commit/435d05394a9e7895d8daf2804bbe3668e1666981): networking.k8s.io/v1beta1
### Updater
- [a14b372](https://github.com/quay/clair/commit/a14b372838a72d24110b57c6443d784d6fbe4451): fix stuck updater process
### Updater
- [7084a22](https://github.com/quay/clair/commit/7084a226ae9c5a3aed1248ad3d653100d610146c): extract deduplicate function
- [e16d17d](https://github.com/quay/clair/commit/e16d17dda9d29e8fdc33ef9da6a4a8be0e6b648f): remove original RunUpdate()
- [0d41968](https://github.com/quay/clair/commit/0d41968acdeeb2325bf9573a65fd1d05345ba255): reimplement fetch() with errgroup
- [6c5be7e](https://github.com/quay/clair/commit/6c5be7e1c6856fbae55e77c0a3411e7fe4d61f82): refactor to use errgroup
- [2236b0a](https://github.com/quay/clair/commit/2236b0a5c9a094bde2b7979417b9538cb944e726): Add vulnsrc affected feature type
- [0d18a62](https://github.com/quay/clair/commit/0d18a629cab15d57fb7b00777f1537039b69401b): sleep before continuing the lock loop
 - Fixes [#415](https://github.com/quay/clair/issues/415)### Updater,Pkg/Timeutil
- [f64bd11](https://github.com/quay/clair/commit/f64bd117b2fa946c26a2e3368925f6dae8e4a2d3): minor cleanups
### Upgrade To Golang
- [db5dbbe](https://github.com/quay/clair/commit/db5dbbe4e983a4ac827f5b6597aac780c03124b3): 1.10-alpine
### V3
- [88f5069](https://github.com/quay/clair/commit/88f506918b9cb32ab77e41e0cbbe2f9db6e6b358): Analyze layer content in parallel
- [dd23976](https://github.com/quay/clair/commit/dd239762f63702c1800895ee9b86bdda316830ef): Move services to top of the file
- [9f5d1ea](https://github.com/quay/clair/commit/9f5d1ea4e16793ebd9390673aed34855671b5c24): associate feature and namespace with detector
### Vendor
- [4106322](https://github.com/quay/clair/commit/41063221075cea67636f77f58a9d3e112771b835): Update gopkg.in/yaml.v2 package
- [34d0e51](https://github.com/quay/clair/commit/34d0e516e0792ca2d06299a1262e5676d4145f80): Add golang-set dependency
- [55ecf1e](https://github.com/quay/clair/commit/55ecf1e58aa75346ca6c4d702eb31e02ff32ee0e): regenerate after removing graceful
- [1533dd1](https://github.com/quay/clair/commit/1533dd1d51d4f89febd857897addb6dfb6c161e4): updated vendor dir for grpc v2 api
### Vulnmdsrc
- [ce6b008](https://github.com/quay/clair/commit/ce6b00887b1db3a402b1a02bdebb5bcc23d4add0): update NVD URLs
 - Fixes [#575](https://github.com/quay/clair/issues/575)### Vulnsrc
- [72674ca](https://github.com/quay/clair/commit/72674ca871dd2b0a9afdbd9c6a6b50f49a50b20b): Refactor vulnerability sources to use utility functions
### Vulnsrc Rhel
- [bd7102d](https://github.com/quay/clair/commit/bd7102d96304b02ff09077edc16f5f60bd784c8b): handle "none" CVE impact
### Vulnsrc/Alpine
- [c031f8e](https://github.com/quay/clair/commit/c031f8ea0c793ba0462f2b8a204c15ab3a65f1a5): s/pull/clone
- [4c2be52](https://github.com/quay/clair/commit/4c2be5285e1419844377c11484bd684b45948958): avoid shadowing vars
### Vulnsrc/Ubuntu
- [456af5f](https://github.com/quay/clair/commit/456af5f48c8da8325266209e58cec90f4a3f1f68): use new git-based ubuntu tracker
### Vulnsrc_oracle
- [3503ddb](https://github.com/quay/clair/commit/3503ddb96fe412242b84ec28f36a7ddd787b823f): one vulnerability per CVE
 -  [#495](https://github.com/quay/clair/issues/495) -  [#499](https://github.com/quay/clair/issues/499)### Vulnsrc_rhel
- [c4ffa0c](https://github.com/quay/clair/commit/c4ffa0c370e793546dd51ea25fc98961c2d25970): cve impact
- [a90db71](https://github.com/quay/clair/commit/a90db713a2722a80db33e47343c4a4d417f48a0e): add test
- [8b3338e](https://github.com/quay/clair/commit/8b3338ef56b060e27bc3d81124f52bbded315f1a): minor changes
- [4e4e98f](https://github.com/quay/clair/commit/4e4e98f328309d1c0a470388d198fa37c27e47d5): minor changes
- [ac86a36](https://github.com/quay/clair/commit/ac86a3674094f93b71e8736392b7a4707fa972fe): rhsa_ID by default
- [4ab98cf](https://github.com/quay/clair/commit/4ab98cfe54bedcce7880cc03b1c52d5a91811860): one vulnerability by CVE
 - Fixes [#495](https://github.com/quay/clair/issues/495)### Worker
- [23ccd9b](https://github.com/quay/clair/commit/23ccd9b53ba0a8bcf800fecdbd72d5cbefd2ea60): Fix tests for feature_type
- [f0e21df](https://github.com/quay/clair/commit/f0e21df7830e3f8d00498936d0d292ae6ff6765b): fixed duplicated ns and ns not inherited bug
### Workflows
- [e1902d4](https://github.com/quay/clair/commit/e1902d4d7c1f7d7fdccc6b339736966d2ece0cf6): proper tag name
- [b2d781c](https://github.com/quay/clair/commit/b2d781c2ed50262f4882e34b2585bf99d80fb15b): bad tar flag
### Pull Requests
- Merge pull request [#949](https://github.com/quay/clair/issues/949) from alecmerdler/PROJQUAY-494
- Merge pull request [#936](https://github.com/quay/clair/issues/936) from ldelossa/louis/interface-refactor
- Merge pull request [#933](https://github.com/quay/clair/issues/933) from ldelossa/louis/config-and-make
- Merge pull request [#930](https://github.com/quay/clair/issues/930) from ldelossa/louis/middleware-packaging
- Merge pull request [#929](https://github.com/quay/clair/issues/929) from ldelossa/louis/cc-bump-v0.0.17
- Merge pull request [#924](https://github.com/quay/clair/issues/924) from ldelossa/louis/severity-mapping
- Merge pull request [#903](https://github.com/quay/clair/issues/903) from ldelossa/louis/environment-api
- Merge pull request [#897](https://github.com/quay/clair/issues/897) from ldelossa/louis/state-json
- Merge pull request [#890](https://github.com/quay/clair/issues/890) from ldelossa/louis/remove-healthhandler
- Merge pull request [#877](https://github.com/quay/clair/issues/877) from mtougeron/update-ingress-apiversion
- Merge pull request [#873](https://github.com/quay/clair/issues/873) from coreos/code-owners-update
- Merge pull request [#867](https://github.com/quay/clair/issues/867) from andrewsharon/ubuntu19.10
- Merge pull request [#861](https://github.com/quay/clair/issues/861) from thekbb/fix-broken-link-i-missed
- Merge pull request [#856](https://github.com/quay/clair/issues/856) from thekbb/fix-links
- Merge pull request [#860](https://github.com/quay/clair/issues/860) from jzelinskie/bump-v2-master
- Merge pull request [#851](https://github.com/quay/clair/issues/851) from Allda/log-fix
- Merge pull request [#774](https://github.com/quay/clair/issues/774) from Allda/updater_fix
- Merge pull request [#839](https://github.com/quay/clair/issues/839) from noahklein/nvd-status-error
- Merge pull request [#829](https://github.com/quay/clair/issues/829) from peacocb/peacocb-828-dos-on-ancestry-post
- Merge pull request [#831](https://github.com/quay/clair/issues/831) from MVrachev/patch-1
- Merge pull request [#818](https://github.com/quay/clair/issues/818) from vsamidurai/master
- Merge pull request [#822](https://github.com/quay/clair/issues/822) from imlonghao/bullseye
- Merge pull request [#817](https://github.com/quay/clair/issues/817) from ldelossa/remove-detectors
- Merge pull request [#755](https://github.com/quay/clair/issues/755) from Allda/openshift_cert
- Merge pull request [#808](https://github.com/quay/clair/issues/808) from coreos/add-louis
- Merge pull request [#797](https://github.com/quay/clair/issues/797) from jzelinskie/drone
- Merge pull request [#805](https://github.com/quay/clair/issues/805) from ldelossa/remove-ancestry-copy
- Merge pull request [#794](https://github.com/quay/clair/issues/794) from ldelossa/local-dev-readme-update
- Merge pull request [#793](https://github.com/quay/clair/issues/793) from ldelossa/local-dev-clair-db
- Merge pull request [#788](https://github.com/quay/clair/issues/788) from ldelossa/helm-local-dev
- Merge pull request [#780](https://github.com/quay/clair/issues/780) from jzelinskie/CODEOWNERS
- Merge pull request [#779](https://github.com/quay/clair/issues/779) from jzelinskie/mailing-list
- Merge pull request [#773](https://github.com/quay/clair/issues/773) from flumm/disco
- Merge pull request [#671](https://github.com/quay/clair/issues/671) from ericysim/amazon
- Merge pull request [#766](https://github.com/quay/clair/issues/766) from Allda/lock_timeout
- Merge pull request [#742](https://github.com/quay/clair/issues/742) from bluelabsio/path-templating
- Merge pull request [#739](https://github.com/quay/clair/issues/739) from joelee2012/master
- Merge pull request [#749](https://github.com/quay/clair/issues/749) from cnorthwood/tarutil-glob
- Merge pull request [#741](https://github.com/quay/clair/issues/741) from KeyboardNerd/parallel_download
- Merge pull request [#738](https://github.com/quay/clair/issues/738) from Allda/potentialNamespaceAncestry
- Merge pull request [#721](https://github.com/quay/clair/issues/721) from KeyboardNerd/cache
- Merge pull request [#735](https://github.com/quay/clair/issues/735) from jzelinskie/fix-sweet32
- Merge pull request [#722](https://github.com/quay/clair/issues/722) from Allda/feature_ns
- Merge pull request [#724](https://github.com/quay/clair/issues/724) from KeyboardNerd/ref
- Merge pull request [#728](https://github.com/quay/clair/issues/728) from KeyboardNerd/fix
- Merge pull request [#727](https://github.com/quay/clair/issues/727) from KeyboardNerd/master
- Merge pull request [#725](https://github.com/quay/clair/issues/725) from KeyboardNerd/license_test
- Merge pull request [#723](https://github.com/quay/clair/issues/723) from jzelinskie/lock-tx
- Merge pull request [#720](https://github.com/quay/clair/issues/720) from KeyboardNerd/update_ns
- Merge pull request [#695](https://github.com/quay/clair/issues/695) from saromanov/fix-unchecked-error
- Merge pull request [#712](https://github.com/quay/clair/issues/712) from KeyboardNerd/builder
- Merge pull request [#672](https://github.com/quay/clair/issues/672) from KeyboardNerd/source_package/feature_type
- Merge pull request [#685](https://github.com/quay/clair/issues/685) from jzelinskie/updater-cleanup
- Merge pull request [#701](https://github.com/quay/clair/issues/701) from dustinspecker/patch-1
- Merge pull request [#700](https://github.com/quay/clair/issues/700) from traum-ferienwohnungen/master
- Merge pull request [#680](https://github.com/quay/clair/issues/680) from Allda/slices
- Merge pull request [#687](https://github.com/quay/clair/issues/687) from jzelinskie/suse-config
- Merge pull request [#686](https://github.com/quay/clair/issues/686) from jzelinskie/fix-presentations
- Merge pull request [#679](https://github.com/quay/clair/issues/679) from kubeshield/master
- Merge pull request [#506](https://github.com/quay/clair/issues/506) from openSUSE/reintroduce-suse-opensuse
- Merge pull request [#681](https://github.com/quay/clair/issues/681) from Allda/rhel_severity
- Merge pull request [#667](https://github.com/quay/clair/issues/667) from travelaudience/helm-tolerations
- Merge pull request [#656](https://github.com/quay/clair/issues/656) from glb/elsa_CVEID
- Merge pull request [#650](https://github.com/quay/clair/issues/650) from Katee/add-ubuntu-cosmic
- Merge pull request [#653](https://github.com/quay/clair/issues/653) from brosander/helm-dep
- Merge pull request [#648](https://github.com/quay/clair/issues/648) from HaraldNordgren/go_versions
- Merge pull request [#647](https://github.com/quay/clair/issues/647) from KeyboardNerd/spkg/cvrf
- Merge pull request [#644](https://github.com/quay/clair/issues/644) from KeyboardNerd/bug/git
- Merge pull request [#645](https://github.com/quay/clair/issues/645) from Katee/include-cvssv3
- Merge pull request [#646](https://github.com/quay/clair/issues/646) from KeyboardNerd/spkg/model
- Merge pull request [#640](https://github.com/quay/clair/issues/640) from KeyboardNerd/sourcePackage
- Merge pull request [#639](https://github.com/quay/clair/issues/639) from Katee/update-sha1-to-sha256
- Merge pull request [#638](https://github.com/quay/clair/issues/638) from KeyboardNerd/featureTree
- Merge pull request [#633](https://github.com/quay/clair/issues/633) from coreos/roadmap-1
- Merge pull request [#620](https://github.com/quay/clair/issues/620) from KeyboardNerd/feature/detector
- Merge pull request [#627](https://github.com/quay/clair/issues/627) from haydenhughes/master
- Merge pull request [#624](https://github.com/quay/clair/issues/624) from jzelinskie/probot
- Merge pull request [#621](https://github.com/quay/clair/issues/621) from jzelinskie/gitutil
- Merge pull request [#610](https://github.com/quay/clair/issues/610) from MackJM/wip/master_nvd_httputil
- Merge pull request [#499](https://github.com/quay/clair/issues/499) from yebinama/rhel_CVEID
- Merge pull request [#619](https://github.com/quay/clair/issues/619) from KeyboardNerd/sidac/rm_layer
- Merge pull request [#617](https://github.com/quay/clair/issues/617) from jzelinskie/grpc-refactor
- Merge pull request [#614](https://github.com/quay/clair/issues/614) from KeyboardNerd/sidac/simplify
- Merge pull request [#613](https://github.com/quay/clair/issues/613) from jzelinskie/pkg-pagination
- Merge pull request [#611](https://github.com/quay/clair/issues/611) from jzelinskie/drop-graceful
- Merge pull request [#605](https://github.com/quay/clair/issues/605) from KeyboardNerd/sidchen/feature
- Merge pull request [#606](https://github.com/quay/clair/issues/606) from MackJM/wip/master_httputil
- Merge pull request [#607](https://github.com/quay/clair/issues/607) from jzelinskie/gofmt
- Merge pull request [#604](https://github.com/quay/clair/issues/604) from jzelinskie/nvd-urls
- Merge pull request [#601](https://github.com/quay/clair/issues/601) from KeyboardNerd/sidchen/status
- Merge pull request [#594](https://github.com/quay/clair/issues/594) from reasonerjt/fix-alpine-url
- Merge pull request [#578](https://github.com/quay/clair/issues/578) from naibaf0/fix/helmtemplate/configmap/postgresql
- Merge pull request [#586](https://github.com/quay/clair/issues/586) from robertomlsoares/update-helm-chart
- Merge pull request [#582](https://github.com/quay/clair/issues/582) from brosander/helm-alpine-postgres
- Merge pull request [#571](https://github.com/quay/clair/issues/571) from ErikThoreson/nvdupdates
- Merge pull request [#574](https://github.com/quay/clair/issues/574) from hongli-my/fix-nvd-path
- Merge pull request [#572](https://github.com/quay/clair/issues/572) from arno01/multi-stage
- Merge pull request [#540](https://github.com/quay/clair/issues/540) from jzelinskie/document-proto
- Merge pull request [#569](https://github.com/quay/clair/issues/569) from jzelinskie/ubuntu-git
- Merge pull request [#553](https://github.com/quay/clair/issues/553) from qeqar/master
- Merge pull request [#551](https://github.com/quay/clair/issues/551) from usr42/upgrade_to_1.10-alpine
- Merge pull request [#538](https://github.com/quay/clair/issues/538) from jzelinskie/dockerize-protogen
- Merge pull request [#537](https://github.com/quay/clair/issues/537) from tomer-1/patch-1
- Merge pull request [#532](https://github.com/quay/clair/issues/532) from KeyboardNerd/readme_typo
- Merge pull request [#508](https://github.com/quay/clair/issues/508) from joerayme/bug/436
- Merge pull request [#528](https://github.com/quay/clair/issues/528) from KeyboardNerd/helm_typo
- Merge pull request [#522](https://github.com/quay/clair/issues/522) from vdboor/master
- Merge pull request [#521](https://github.com/quay/clair/issues/521) from yebinama/paclair
- Merge pull request [#518](https://github.com/quay/clair/issues/518) from traum-ferienwohnungen/master
- Merge pull request [#513](https://github.com/quay/clair/issues/513) from leandrocr/patch-1
- Merge pull request [#517](https://github.com/quay/clair/issues/517) from KeyboardNerd/master
- Merge pull request [#505](https://github.com/quay/clair/issues/505) from ericchiang/coc
- Merge pull request [#484](https://github.com/quay/clair/issues/484) from odg0318/master
- Merge pull request [#498](https://github.com/quay/clair/issues/498) from bkochendorfer/contributing-link
- Merge pull request [#482](https://github.com/quay/clair/issues/482) from yfoelling/patch-1
- Merge pull request [#487](https://github.com/quay/clair/issues/487) from ajgreenb/db-connection-backoff
- Merge pull request [#488](https://github.com/quay/clair/issues/488) from caulagi/patch-1
- Merge pull request [#485](https://github.com/quay/clair/issues/485) from yebinama/proxy
- Merge pull request [#481](https://github.com/quay/clair/issues/481) from coreos/stable-release-issue-template
- Merge pull request [#479](https://github.com/quay/clair/issues/479) from yebinama/nvd_vectors
- Merge pull request [#477](https://github.com/quay/clair/issues/477) from bseb/master
- Merge pull request [#469](https://github.com/quay/clair/issues/469) from zamarrowski/master
- Merge pull request [#475](https://github.com/quay/clair/issues/475) from dctrud/clair-singularity
- Merge pull request [#467](https://github.com/quay/clair/issues/467) from grebois/master
- Merge pull request [#465](https://github.com/quay/clair/issues/465) from jzelinskie/github
- Merge pull request [#463](https://github.com/quay/clair/issues/463) from brunomcustodio/fix-ingress
- Merge pull request [#459](https://github.com/quay/clair/issues/459) from arthurlm44/patch-1
- Merge pull request [#458](https://github.com/quay/clair/issues/458) from jzelinskie/linux-vulns
- Merge pull request [#450](https://github.com/quay/clair/issues/450) from jzelinskie/move-token
- Merge pull request [#454](https://github.com/quay/clair/issues/454) from InTheCloudDan/helm-tls-option
- Merge pull request [#455](https://github.com/quay/clair/issues/455) from zmarouf/master
- Merge pull request [#449](https://github.com/quay/clair/issues/449) from jzelinskie/helm
- Merge pull request [#447](https://github.com/quay/clair/issues/447) from KeyboardNerd/ancestry_
- Merge pull request [#448](https://github.com/quay/clair/issues/448) from jzelinskie/woops
- Merge pull request [#444](https://github.com/quay/clair/issues/444) from jzelinskie/docs-refresh
- Merge pull request [#432](https://github.com/quay/clair/issues/432) from KeyboardNerd/ancestry_
- Merge pull request [#442](https://github.com/quay/clair/issues/442) from arminc/add-integration-clari-scanner
- Merge pull request [#433](https://github.com/quay/clair/issues/433) from mssola/portus-integration
- Merge pull request [#408](https://github.com/quay/clair/issues/408) from KeyboardNerd/grpc
- Merge pull request [#423](https://github.com/quay/clair/issues/423) from jzelinskie/sleep-updater
- Merge pull request [#418](https://github.com/quay/clair/issues/418) from KeyboardNerd/multiplens
- Merge pull request [#410](https://github.com/quay/clair/issues/410) from KeyboardNerd/xforward
- Merge pull request [#416](https://github.com/quay/clair/issues/416) from tianon/debian-buster
- Merge pull request [#413](https://github.com/quay/clair/issues/413) from transcedentalia/master
- Merge pull request [#403](https://github.com/quay/clair/issues/403) from KeyboardNerd/multiplens
- Merge pull request [#407](https://github.com/quay/clair/issues/407) from swestcott/kubernetes-config-fix
- Merge pull request [#394](https://github.com/quay/clair/issues/394) from KeyboardNerd/multiplens
- Merge pull request [#382](https://github.com/quay/clair/issues/382) from caipre/patch-1


[Unreleased]: https://github.com/quay/clair/compare/v4.0.0-rc.4...HEAD
[v4.0.0-rc.4]: https://github.com/quay/clair/compare/v2.1.5...v4.0.0-rc.4
[v2.1.5]: https://github.com/quay/clair/compare/v4.0.0-rc.3...v2.1.5
[v4.0.0-rc.3]: https://github.com/quay/clair/compare/v4.0.0-rc.2...v4.0.0-rc.3
[v4.0.0-rc.2]: https://github.com/quay/clair/compare/v4.0.0-rc.1...v4.0.0-rc.2
[v4.0.0-rc.1]: https://github.com/quay/clair/compare/v4.0.0-alpha.test...v4.0.0-rc.1
[v4.0.0-alpha.test]: https://github.com/quay/clair/compare/v4.0.0-alpha.7...v4.0.0-alpha.test
[v4.0.0-alpha.7]: https://github.com/quay/clair/compare/v2.1.4...v4.0.0-alpha.7
[v2.1.4]: https://github.com/quay/clair/compare/qui-gon...v2.1.4
[qui-gon]: https://github.com/quay/clair/compare/v4.0.0-alpha.6...qui-gon
[v4.0.0-alpha.6]: https://github.com/quay/clair/compare/v4.0.0-alpha.5...v4.0.0-alpha.6
[v4.0.0-alpha.5]: https://github.com/quay/clair/compare/v4.0.0-alpha.4...v4.0.0-alpha.5
[v4.0.0-alpha.4]: https://github.com/quay/clair/compare/v2.1.3...v4.0.0-alpha.4
[v2.1.3]: https://github.com/quay/clair/compare/v4.0.0-alpha.3...v2.1.3
[v4.0.0-alpha.3]: https://github.com/quay/clair/compare/v4.0.0-alpha.2...v4.0.0-alpha.3
[v4.0.0-alpha.2]: https://github.com/quay/clair/compare/v2.1.2...v4.0.0-alpha.2
