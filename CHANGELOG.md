<a name="unreleased"></a>
## [Unreleased]


<a name="v4.1.0"></a>
## [v4.1.0] - 2021-03-23
### All
- [6638793](https://github.com/quay/clair/commit/66387930f2b80087a32a1aeddc9b1ef16eec01e1): use RateLimiter where it seems appropriate
### Chore
- [04f2cb7](https://github.com/quay/clair/commit/04f2cb71acc8eceac0d1a7766c5ebfcfa01150ee): bump claircore version
### Cicd
- [8b0cdb3](https://github.com/quay/clair/commit/8b0cdb38fa8f4d701e0ef804e37728721798f564): use golang major version tag for dev env
- [c1895c4](https://github.com/quay/clair/commit/c1895c433dfc3a872cce2c1468801ecdddf2e962): use quay.io/projectquay/golang image
### Claircore
- [bc2b059](https://github.com/quay/clair/commit/bc2b0591d3ea3a07498820bc625f7dc9cd5ce934): update to use new libvuln API
### Clairctl
- [c80a99d](https://github.com/quay/clair/commit/c80a99d14ed96e539a79212fb23f608a03ee636c): move to updates.Manager interface
- [30f8696](https://github.com/quay/clair/commit/30f86961b88b7a590157f28fc6cb8f22f16dfa06): move to zlog
### Httputil
- [ed8ffc5](https://github.com/quay/clair/commit/ed8ffc50b56c9b11873f00bb2deb4fba9107ec95): create package and RateLimiter
### Initialize
- [5df82e1](https://github.com/quay/clair/commit/5df82e19e971c67ebdecf3f92682d4ae897db53a): update call to Libindex constructor
### Introspection
- [ec59a43](https://github.com/quay/clair/commit/ec59a431032713654e2eb7a29ad7c446dd16a490): enable readiness endpoint

<a name="v4.1.0-alpha.3"></a>
## [v4.1.0-alpha.3] - 2021-05-04
### Chore
- [f3d64ff](https://github.com/quay/clair/commit/f3d64ffc3f3b8ebcf4d91d60117e8a268d840fd8): v4.1.0-alpha.3 changelog bump
- [01c44cc](https://github.com/quay/clair/commit/01c44cc39dd5d5c644d6849dfe204a1ffd02bab8): update claircore revision
### Cicd
- [4535b9f](https://github.com/quay/clair/commit/4535b9f41c310b3d590e2e0d8e3758d0d39d5105): changelog fixups
### Config
- [1f9b565](https://github.com/quay/clair/commit/1f9b56577957ce28044b221af58b160328a671a2): validate based on combo mode or not
### Httptransport
- [9e67501](https://github.com/quay/clair/commit/9e67501d818045749c4f263128b72e7cb6856bd1): fix LatestUpdateOperations method
### Notifier
- [6d33153](https://github.com/quay/clair/commit/6d331530c7a8714a16d32ce3ca6e74ec8afc5184): check msg contents in integration tests
- [cc4a10f](https://github.com/quay/clair/commit/cc4a10ffedfc2edaae229cd953b3602ca16da2ec): remove direct zerolog use
### Tests
- [08734ab](https://github.com/quay/clair/commit/08734ab233457dc4bba1b071331f0c8024f6b4dd): fix small unit test race
- [6e50ec2](https://github.com/quay/clair/commit/6e50ec2eec4eb50711ac48f14181e5a7ca075a70): add testing command
- [1e92bd2](https://github.com/quay/clair/commit/1e92bd241ba42eec3cca6c8e983ba937caa23bd9): fix small race

<a name="v4.1.0-alpha.2"></a>
## [v4.1.0-alpha.2] - 2021-04-09
### Chore
- [e0eea38](https://github.com/quay/clair/commit/e0eea383b9e791b5b041136b88f1b69b3d4841bb): v4.1.0-alpha.2 changelog bump
### Codec
- [d5cac13](https://github.com/quay/clair/commit/d5cac1315481a87f596f395e1c2da2bf57eaf18c): use stdlib time.Time encoding
 - Closes [#1231](https://github.com/quay/clair/issues/1231)### Docs
- [60f9684](https://github.com/quay/clair/commit/60f9684accfd7e6b9e1bd585a55874803e1160f5): minor updates
- [cbdc9ca](https://github.com/quay/clair/commit/cbdc9caab450489377ab1d6bb19429d54df639cc): update configuration file reference

<a name="v4.1.0-alpha.1"></a>
## [v4.1.0-alpha.1] - 2021-04-05
### All
- [a5bfaeb](https://github.com/quay/clair/commit/a5bfaeb33cc43350234345aba0059a02098f0d67): switch to using codec package
### Chore
- [493beb1](https://github.com/quay/clair/commit/493beb13d3a9d0739bcffa74217f7e2107f8438d): v4.1.0-alpha.1 changelog bump
- [4734435](https://github.com/quay/clair/commit/473443575e0160cdc83574dcd48982d9922ddf4e): v4.1.0-alpha.1 changelog bump
- [6e8a838](https://github.com/quay/clair/commit/6e8a838305c6bdc6a71e3b3a9ee5735660ebbd22): bump cc to v0.4.0
- [5a6f1c3](https://github.com/quay/clair/commit/5a6f1c3b24f9c178838e905a1435078f9706a7b9): update claircore version for database fix
- [ea0378d](https://github.com/quay/clair/commit/ea0378d4d67376ebb924b7fb78d4d4f22ad9e1de): bump cc v0.3.0
- [6e195c9](https://github.com/quay/clair/commit/6e195c99a14139360c8d09f90c94024eb7d27b67): fix yaml file indentation issue
### Cicd
- [b1145e3](https://github.com/quay/clair/commit/b1145e3a1c5e8faf3d1a64a403de940386b73102): sort changelog by semver
- [7dc55fa](https://github.com/quay/clair/commit/7dc55fa9bb0b968ab580c7d6d0ea4ffa053eaba0): bump in go.16, bump out go1.14
- [d5e57af](https://github.com/quay/clair/commit/d5e57afb594d58cf817a962d9e282c820ab6577e): enable CI on stable branches
- [f7737e5](https://github.com/quay/clair/commit/f7737e58cfca3640d4a901a658317becb47ba2af): fix openshift ci/cd script
- [30c0311](https://github.com/quay/clair/commit/30c0311a8b1584a40f5b956b3b3d9e9ab7eee18a): update golang container for go-mod in app-sre
- [cb656df](https://github.com/quay/clair/commit/cb656dfbd69ff1ce11976c7de672b50277091ab8): add notifier to app interface
- [9254ab6](https://github.com/quay/clair/commit/9254ab66ea7f1b9711242026045da35b7ffa2782): use quay.io image in CI and Dockerfile
### Clair
- [ecd8999](https://github.com/quay/clair/commit/ecd8999cbfd6b9140f0aa8aebc11a67cbefcb4d2): fix initialization error logging
- [dc2f893](https://github.com/quay/clair/commit/dc2f8936a564fbc234e1b8f00a3eb4778452f2ec): reorganize initialization
- [391c2f7](https://github.com/quay/clair/commit/391c2f766bcbf9c2392c12dca2bb9f225f1ef424): add Shutdown struct
### Claircore
- [f183421](https://github.com/quay/clair/commit/f1834212272b07f02228b04a67e9339001dc51f8): bump to v0.2.0
### Clairctl
- [5740a1b](https://github.com/quay/clair/commit/5740a1b0427c81ae5f447add372db43a1ec73dbf): Add subpath to clairctl
### Client
- [bd50a95](https://github.com/quay/clair/commit/bd50a9570d996578e0209286a66ec3d7f41d6aaf): remove request body buffering
- [ce11fd7](https://github.com/quay/clair/commit/ce11fd7077c2fb10715b37a8248b42583d930462): fix panic on request failure
 -  [#1186](https://github.com/quay/clair/issues/1186)### Codec
- [1fb6dcf](https://github.com/quay/clair/commit/1fb6dcfd32143520aa348b184e865be7a6081134): add package for codec pooling
### Config
- [e9390fa](https://github.com/quay/clair/commit/e9390fadc24e53e455360f709e79674f752c4a29): add matchers settings
- [eb519e0](https://github.com/quay/clair/commit/eb519e0752d3cf7f5f8daeefd4ad9bd29cbfa8c2): allow gc to be disabled
- [f2d7313](https://github.com/quay/clair/commit/f2d731341722e3d59c9351c10b7e8eedbe74f276): rework into specific validators
### Docs
- [0f230f9](https://github.com/quay/clair/commit/0f230f99f22150a00b36654ee8a5a7674e5507f7): add support matrix
- [102ae88](https://github.com/quay/clair/commit/102ae88dd84c1f769b8c037226d92b301d887aab): update cli reference
- [9d0a2b2](https://github.com/quay/clair/commit/9d0a2b20a6808f0e86cbd4f2a6046a6c7abdc2ea): fix psk related config references
- [44303dc](https://github.com/quay/clair/commit/44303dccfd26935fd66ff041e22602c709c4a428): install clairctl correctly
- [a3bb1b6](https://github.com/quay/clair/commit/a3bb1b6d8caebf228ac39b8793d5326bea0d1b55): use correct clairctl subcommands
 - Closes [#1122](https://github.com/quay/clair/issues/1122)### Documentation
- [2e65925](https://github.com/quay/clair/commit/2e6592500fbe9c3197782133965de6503b07b6ab): modified testing.md for clarity
 -  [#1180](https://github.com/quay/clair/issues/1180)### Httptransport
- [21dc720](https://github.com/quay/clair/commit/21dc720a7f1e63e731eadbf72cf192913bf88c39): add mime type to indexer and matcher handler
- [8616cc6](https://github.com/quay/clair/commit/8616cc68b030fc417c693b3d2dc7208015ce9f4e): return Accepted when not ready
- [1ac26da](https://github.com/quay/clair/commit/1ac26daf5501876495ec09f4e67b50eaca4bd1a5): fix panic in metrics registration
- [7305b3d](https://github.com/quay/clair/commit/7305b3d735786e340833e045e2cd5888c8af866b): use correct handler for state endpoint
- [df5e7f9](https://github.com/quay/clair/commit/df5e7f9658b1fed55d067013656115b062127c23): check for err before deferring resp.Body.Close()
### Initialize
- [8a2df09](https://github.com/quay/clair/commit/8a2df099fe2e69a572e8d81b352f688f82de341a): remove New function
- [2d27ae5](https://github.com/quay/clair/commit/2d27ae5cd3fe55737c2fa02b46616ec09ade47c5): add standalone initialization functions
### Instrospection
- [b78f954](https://github.com/quay/clair/commit/b78f954dbf3210f7deb87dc371b1d35cba216d78): bump to opentelemetry 0.16.0
### Introspection
- [1ece08f](https://github.com/quay/clair/commit/1ece08f49434828c8c672f08ec45844b99187983): database metrics for notifier
- [84ba35f](https://github.com/quay/clair/commit/84ba35f29ee81849cb2f424b3624895f9bd05a79): implement prometheus http
### Local-Dev
- [1c85589](https://github.com/quay/clair/commit/1c85589abdef98b5af8d4f6e2cd9eb5db6a723a0): remove unintended change in config.yaml
### Logging
- [9f3d167](https://github.com/quay/clair/commit/9f3d167d5d85d345c7d0ee666be075a545a553f4): move to zlog throughout
### Matcher
- [858c540](https://github.com/quay/clair/commit/858c540b2ef9b8d7f71d16bbe3ba797f73f654ab): add Initialized method
### Notifier
- [e7bf3b1](https://github.com/quay/clair/commit/e7bf3b1730e04ad10ec4baef1643556bf5626090): construct notification objects directly
- [9962202](https://github.com/quay/clair/commit/99622021c594149a0b0d183b6349e2ee7139e5d2): do AffectedManifests calls in chunks
### Severity_mapping
- [8e39fa4](https://github.com/quay/clair/commit/8e39fa40eebca7b50ab29f0001686fa7c5c49e1e): remove defcon1 severity
### Updaters
- [8105b03](https://github.com/quay/clair/commit/8105b033fb53f0907373f6af76af954fe95a856d): plumb update retention in

<a name="v4.0.5"></a>
## [v4.0.5] - 2021-04-16
### Chore
- [b92ba98](https://github.com/quay/clair/commit/b92ba981540bf13344f5fe48d5683fd2c600e92b): v4.0.5 changelog bump
- [486ccfb](https://github.com/quay/clair/commit/486ccfb9d8baac5f468acf0cc0752d7d2d9f8ce4): bump cc stable to v0.1.25

<a name="v4.0.4"></a>
## [v4.0.4] - 2021-03-25
### Chore
- [4bfd7d1](https://github.com/quay/clair/commit/4bfd7d11c3f1290af889e258283f585f5f4abbd4): v4.0.4 changelog bump
- [4ff4c90](https://github.com/quay/clair/commit/4ff4c9082573cadf8c96b6e4f5e67aa46ac31699): bump cc to stable v0.1.24
### Cicd
- [0800ba4](https://github.com/quay/clair/commit/0800ba46b160c30c623f0ad7062fe7882604233e): sort changelog by semver
### Initialize
- [7c4787b](https://github.com/quay/clair/commit/7c4787bfb1585d54f0ef371487228cb4941db5a0): wire up DisableUpdaters option

<a name="v4.0.3"></a>
## [v4.0.3] - 2021-03-12
### Chore
- [a844fb2](https://github.com/quay/clair/commit/a844fb2290bdaeb2d6f99c013e1ea3ab2b17dc6f): v4.0.3 changelog bump
- [a26eb80](https://github.com/quay/clair/commit/a26eb80d83bf0e993ccd7df977be6bc456a0de4c): bump cc stable to v0.1.23

<a name="v4.0.2"></a>
## [v4.0.2] - 2021-02-18
### Chore
- [5c236e6](https://github.com/quay/clair/commit/5c236e6d2afe05c92245f817337341ae6478125d): 4.0.2 changelog bump
### Client
- [8b63953](https://github.com/quay/clair/commit/8b63953e99e0246a9428205cf51c66ec3af65ba3): fix panic on request failure
 -  [#1186](https://github.com/quay/clair/issues/1186) -  [#1188](https://github.com/quay/clair/issues/1188)
<a name="v4.0.1"></a>
## [v4.0.1] - 2021-02-15
### Chore
- [8a392f1](https://github.com/quay/clair/commit/8a392f1bd3a381e98ece87e9ccd4842113563bb4): v4.0.1 changelog bump
- [c47be87](https://github.com/quay/clair/commit/c47be87d6fbb0a34960001a45246d3936e5f8710): bump cc to v0.1.22 stable

<a name="v4.0.0"></a>
## [v4.0.0] - 2020-12-15
### Chore
- [73cdf7d](https://github.com/quay/clair/commit/73cdf7d904a1aa6341a27c3ecae11c89d7444e39): v4.0.0 changelog bump
### Reverts
- Dockerfile: Get build image from Quay instead of DockerHub
- cicd: use golang image from quay.io


<a name="v4.0.0-rc.24"></a>
## [v4.0.0-rc.24] - 2020-12-11
### Chore
- [d3b3497](https://github.com/quay/clair/commit/d3b3497d997020a879eca1190150ce73642d90b9): v4.0.0-rc.24 changelog bump
- [0515f09](https://github.com/quay/clair/commit/0515f09a2fbc4f5a29fda476f6be1f0e77f5d8fa): bump cc to v0.1.20

<a name="v4.0.0-rc.23"></a>
## [v4.0.0-rc.23] - 2020-12-07
### Chore
- [2080ece](https://github.com/quay/clair/commit/2080ece3032daf0f28f85dd07749886a451cf71f): v4.0.0-rc.23 changelog bump
- [289208c](https://github.com/quay/clair/commit/289208cfab02b587366434372e5295150306abf2): bump cc to v0.1.19
### Cicd
- [30444f3](https://github.com/quay/clair/commit/30444f3b782044373ab174ffa2628aaf9495d832): use golang image from quay.io

<a name="v4.0.0-rc.22"></a>
## [v4.0.0-rc.22] - 2020-12-02
### Chore
- [8ef8509](https://github.com/quay/clair/commit/8ef8509753387e1dcdf709e71fee16cbdd7146f9): v4.0.0-rc.22 changelog bump
- [bbe1cd8](https://github.com/quay/clair/commit/bbe1cd8f19f62a0becbd110d27cb20b6bd699f36): claircore v0.1.18 bump
### Documentation
- [d962bef](https://github.com/quay/clair/commit/d962bef8140516c739e322a7406c0068e2164d45): update links in howto/api

<a name="v4.0.0-rc.21"></a>
## [v4.0.0-rc.21] - 2020-12-01
### Chore
- [c6933f0](https://github.com/quay/clair/commit/c6933f0ab78810eeb8dd3fb66cea0d86e9a7d1de): v4.0.0-rc.21 changelog bump
- [5648439](https://github.com/quay/clair/commit/5648439518cbf10b44fc7fac8a3710c044487bb8): bump cc to v0.0.17
### Cidi
- [a576bf2](https://github.com/quay/clair/commit/a576bf290ba9ccbae5d869a5f12ff2897585a2c0): bump create pull request action
### Clairctl
- [835af27](https://github.com/quay/clair/commit/835af272fad49342f51adb4633ff639de3cc14a1): fix and codify import arguments
- [b9ef107](https://github.com/quay/clair/commit/b9ef1073ca48ed5ed7caaa3e0fbad03a7d83592c): update import and export online help
- [9883e80](https://github.com/quay/clair/commit/9883e80f331190e60de711b0705e9b37017fc5b1): unify config, client handling
### Config
- [dc8ba89](https://github.com/quay/clair/commit/dc8ba8912fa482378ef393aa51b4e9528d2877f2): expose notification summary toggle
- [bb3cd66](https://github.com/quay/clair/commit/bb3cd669f66345aaa0fc5df6f502f34922cc069e): add 'omitempty' to 'updaters' config struct for correct marshalling
### Direct-Delivery
- [ea564d4](https://github.com/quay/clair/commit/ea564d489f2cb8b43c6ea1c90eb40bbcf39ebc63): Fix slices in direct notifier
### Dockerfile
- [c18563d](https://github.com/quay/clair/commit/c18563d90b5ca9d6185f1e503c54912bcdee7564): Get build image from Quay instead of DockerHub
### Docs
- [425fc38](https://github.com/quay/clair/commit/425fc38af9837527421ebf550259f9d7e8371039): add clairctl's new powers to the reference
- [f4169c4](https://github.com/quay/clair/commit/f4169c43d283ede2678ab620db5fa4ee9d6b2c37): Add information about AMQP delivery compatibility
### Local-Dev
- [550f6b9](https://github.com/quay/clair/commit/550f6b93b178846b243585d912c7d6efdd6abcae): fix pgadmin name
### Notifier
- [153f3e3](https://github.com/quay/clair/commit/153f3e3682921b84249950ddfbd186d825377bef): add summary tests
- [dd2e16d](https://github.com/quay/clair/commit/dd2e16db6e952fd5135dadb99ce8ec4b6ea65361): optionally disable per-manifest summary
- [77ca653](https://github.com/quay/clair/commit/77ca6535649c4860b17d345505d44c0511d12bb0): log failed delivery reason

<a name="v4.0.0-rc.20"></a>
## [v4.0.0-rc.20] - 2020-11-02
### Chore
- [ba70ca3](https://github.com/quay/clair/commit/ba70ca3eda70c4654d0f44348ec89231dfb40f44): v4.0.0-rc.20 changelog bump
- [e0e1f0d](https://github.com/quay/clair/commit/e0e1f0dbcd8e7ff46b3c34066f9e894ce124e84f): bump claircore to v0.1.15

<a name="v4.0.0-rc.19"></a>
## [v4.0.0-rc.19] - 2020-10-26
### Chore
- [ecdcc8e](https://github.com/quay/clair/commit/ecdcc8ea104161ecbc36edd7cbf2d6e49e1f836d): v4.0.0-rc.19 changelog bump
### Config
- [157628d](https://github.com/quay/clair/commit/157628dfe1c7f1f837dc8df0e622a2d64a31c79a): add custom config marshaling
### Go.Mod
- [1d4f6c3](https://github.com/quay/clair/commit/1d4f6c33fa314f9a550ba4b2701ec208aff9c93f): new claircore version

<a name="v4.0.0-rc.18"></a>
## [v4.0.0-rc.18] - 2020-10-21
### Chore
- [f0881e4](https://github.com/quay/clair/commit/f0881e4a16050a902dc1df3afe77f7ea280d77ef): v4.0.0-rc.18 changelog bump
### Notifier
- [40abaa6](https://github.com/quay/clair/commit/40abaa67e5b3e4453d6e6cf2ec3452a0c3570f42): do less work

<a name="v4.0.0-rc.17"></a>
## [v4.0.0-rc.17] - 2020-10-19
### Chore
- [37f7791](https://github.com/quay/clair/commit/37f7791287d28de53828ee35c139dc78d5f3e962): claircore bump v0.1.13
### Cicd
- [d2bc2b6](https://github.com/quay/clair/commit/d2bc2b6cda9ff609e0e9883467095f6e425cdae9): remove deprecated set-env commands
- [0cfda4d](https://github.com/quay/clair/commit/0cfda4ddf6a86f01fddd8b8143ce4f64b23a0527): update documentation action
- [49e01d6](https://github.com/quay/clair/commit/49e01d60feeb9fdce618d82b7b328f80bdb4fa89): fix container build
### Clairctl
- [2363778](https://github.com/quay/clair/commit/2363778b4086a62de55cef1afa8f3c519328ec25): add environment variables for clairctl
### Docs
- [dc4bda4](https://github.com/quay/clair/commit/dc4bda499e7aeed655536aa8409b6512113eb7ea): add Makefile target to build docs website
### Local-Dev
- [15b607a](https://github.com/quay/clair/commit/15b607a98e92d87f083d4ca406c7d795fc373cd5): add pgadmin4 container
### Notifier
- [673bd0f](https://github.com/quay/clair/commit/673bd0fe32d5422e8eb3dff3716a2bfce81b891c): fix poller loop

<a name="v4.0.0-rc.16"></a>
## [v4.0.0-rc.16] - 2020-10-09
### Chore
- [88407e2](https://github.com/quay/clair/commit/88407e254d33b7c66e0484ee980daa3f69b1683e): v4.0.0-rc.16 changelog bump
### Cicd
- [96909bf](https://github.com/quay/clair/commit/96909bf3bfca47c8ea1ce0b53d9d5b7e9897b55e): exclude darwin/arm64
- [7786d7d](https://github.com/quay/clair/commit/7786d7d34b01b48f9d2d87682faa54936c25a21f): more debugging
- [89c26ec](https://github.com/quay/clair/commit/89c26ec55443050d2e3dd425b4e37a15fe96c061): more debugging
- [7a1eeaf](https://github.com/quay/clair/commit/7a1eeafd0bebc261f356f05244c3a946bfee8c87): make sure the workspace exists
- [68c0318](https://github.com/quay/clair/commit/68c0318b1b225387402a3d4e66c1803f64fd1d98): make empty changelog on manual trigger
- [4e5ee29](https://github.com/quay/clair/commit/4e5ee2908d49191f54951cc276cf95387f90b83c): rig up a workflow_dispatch to help debugging

<a name="v4.0.0-rc.15"></a>
## [v4.0.0-rc.15] - 2020-10-09
### Chore
- [8d87481](https://github.com/quay/clair/commit/8d87481b80e495c52c8677eae2db1e288576dcb1): v4.0.0-rc.15 changelog bump
### Cicd
- [d758248](https://github.com/quay/clair/commit/d758248755fe18f4658eee93cc5d40dc2b206c06): maybe there's some newline issues

<a name="v4.0.0-rc.14"></a>
## [v4.0.0-rc.14] - 2020-10-09
### Chore
- [e46b4f8](https://github.com/quay/clair/commit/e46b4f89aa2a4a13062c2dd4726b66d476ef8b24): v4.0.0-rc.14 changelog bump
### Cicd
- [58a987d](https://github.com/quay/clair/commit/58a987d6078506357933b378c299576bf15e39c8): invalid goos+goarch pair

<a name="v4.0.0-rc.13"></a>
## [v4.0.0-rc.13] - 2020-10-09
### Chore
- [6326327](https://github.com/quay/clair/commit/63263273a7440cb93fcd044a33ad2d0b5a70f425): v4.0.0-rc.13 changelog bump
### Cicd
- [f6a28c2](https://github.com/quay/clair/commit/f6a28c2dcc252b4e8be08158a227b8fed7b71b27): fix goos/goarch

<a name="v4.0.0-rc.12"></a>
## [v4.0.0-rc.12] - 2020-10-08
### Chore
- [61ce675](https://github.com/quay/clair/commit/61ce675946bd186f5a0be800ab26cad3f008a0f1): v4.0.0-rc.12 changelog bump
### Cicd
- [28dcd94](https://github.com/quay/clair/commit/28dcd9443f95c4243a94896b04ff7b3075a1c21c): parallelize release process, keep test failures
### Clairctl
- [b1fee08](https://github.com/quay/clair/commit/b1fee08e43401fdbe6fd9af222bbe64b6412c773): update some interactive help
### Go.Mod
- [af868db](https://github.com/quay/clair/commit/af868db100705074f718f1a8f7caaafaa8b88220): update dependencies
### Local-Dev
- [3b60292](https://github.com/quay/clair/commit/3b60292591900173f4eda02461d3891e48d070c2): make quay container ignore validations
### Notifier
- [0c1554e](https://github.com/quay/clair/commit/0c1554e9aa6cb8d1116376bf303c8af8e5112b23): ensure Content-Type header present in webhook notification
- [a2d5f9b](https://github.com/quay/clair/commit/a2d5f9b92371094ade82b8f9bef19d72fb8addcd): copy url struct
### Pull Requests
- Merge pull request [#1086](https://github.com/quay/clair/issues/1086) from alecmerdler/webhook-notifier-headers


<a name="v4.0.0-rc.11"></a>
## [v4.0.0-rc.11] - 2020-10-02
### Chore
- [f9f8635](https://github.com/quay/clair/commit/f9f86350521ed9c02258c713a992d76976fab9cc): v4.0.0-rc.11 changelog bump
### Config
- [a4e0410](https://github.com/quay/clair/commit/a4e04105cb15173ee3b06090de7573540969a89c): allow HTTP client to specify claims
- [5aba727](https://github.com/quay/clair/commit/5aba72783bff70fa41769cbe33365a34835bd73f): ensure yaml/json struct tag for auth 'Issuer' field are the same
### Notifier
- [57e1ed0](https://github.com/quay/clair/commit/57e1ed0a1178ca5b980f65e5030a00a82acf52c8): pass configured client into notifier
### Pull Requests
- Merge pull request [#1078](https://github.com/quay/clair/issues/1078) from alecmerdler/fix-issuer-struct-tag


<a name="v4.0.0-rc.10"></a>
## [v4.0.0-rc.10] - 2020-10-01
### Chore
- [2c54a82](https://github.com/quay/clair/commit/2c54a82467af83db44b9dcccdfb73a320699426b): v4.0.0-rc.10 changelog bump
### Cicd
- [f04bc76](https://github.com/quay/clair/commit/f04bc76c666b3d1c5098dcc14b928a165066549a): api reference check
### Docs
- [0d8a2a4](https://github.com/quay/clair/commit/0d8a2a4aae8358597e3b67cbf4deb8be79e76dec): bump api reference
### Go.Mod
- [bd1a3b7](https://github.com/quay/clair/commit/bd1a3b772c2dbd6ae87a94c5608f1cdc2bf0044a): update claircore version
### Httptransport
- [2c9762b](https://github.com/quay/clair/commit/2c9762b0351449b5b09249da513178b3d2757985): remove redundant method check
### Openapi
- [015d862](https://github.com/quay/clair/commit/015d862dce63068951d145c5512ec95977262a03): yamllint and spellcheck
- [d06dabf](https://github.com/quay/clair/commit/d06dabfe57fbb90ba376e8f1fa81d18db90ed070): change OperationIDs for notification endpoints

<a name="v4.0.0-rc.9"></a>
## [v4.0.0-rc.9] - 2020-09-29
### Cicd
- [04fab4a](https://github.com/quay/clair/commit/04fab4a7ef9344ee5e3578c60873a5e56bff64b7): build container with local checkout

<a name="v4.0.0-rc.8"></a>
## [v4.0.0-rc.8] - 2020-09-29
### Chore
- [6181cc6](https://github.com/quay/clair/commit/6181cc6c7a47203482f420ccd257318a0d478978): v4.0.0-rc.8 changelog bump
### Cicd
- [7520b09](https://github.com/quay/clair/commit/7520b0912967a0811660ead8e35f80d85899c000): fix container building

<a name="v4.0.0-rc.7"></a>
## [v4.0.0-rc.7] - 2020-09-29
### Chore
- [9282d29](https://github.com/quay/clair/commit/9282d299fda9f1dee321d0f9b883651e18bf4bf8): v4.0.0-rc.7 changelog bump
### Cicd
- [195ce7a](https://github.com/quay/clair/commit/195ce7a59a5db9d7e1f854e25242434e82635fa7): move container building out of container

<a name="v4.0.0-rc.6"></a>
## [v4.0.0-rc.6] - 2020-09-29
### Chore
- [2f5756d](https://github.com/quay/clair/commit/2f5756de91a4367c4ebda047f2dcbc29bf252d6f): v4.0.0-rc.6 changelog bump
### Cicd
- [f6aa6e6](https://github.com/quay/clair/commit/f6aa6e6e028f73c5ae05e65e2c870972fa04393d): use multiline string for clairctl build command

<a name="v4.0.0-rc.5"></a>
## [v4.0.0-rc.5] - 2020-09-29
### Chore
- [9b9ab32](https://github.com/quay/clair/commit/9b9ab323147b14dbd9fecf4c0620c8f34ae7b23a): v4.0.0-rc.5 changelog bump
### Cicd
- [9aa8adc](https://github.com/quay/clair/commit/9aa8adc10d4e48b01abff666e160b498d982124a): fix clairctl builds

<a name="v4.0.0-rc.4"></a>
## [v4.0.0-rc.4] - 2020-09-29
### Chore
- [31adc6d](https://github.com/quay/clair/commit/31adc6dec374eb2ff1a08cf1154d327cf5f30865): v4.0.0-rc.4 changelog bump
- [d141c5c](https://github.com/quay/clair/commit/d141c5cac5d4e4b13f614ebedb89c99ee3ebf8b0): bump claircore to v0.1.9
- [cd34ea9](https://github.com/quay/clair/commit/cd34ea9e264a8690bb88866f96a407949b14b0a1): remove unused files
### Cicd
- [600c737](https://github.com/quay/clair/commit/600c737c659ea03a6695cc6c0dda0f1d8cce4497): constrain changelog
- [c447bcc](https://github.com/quay/clair/commit/c447bcce4ce4546228b91559c85108ec7a3194af): commit check regexp fix
- [54ee2d2](https://github.com/quay/clair/commit/54ee2d25cd05593edc38a94103bef459f6219c4b): change log generation and releases
### Docs
- [d34acaf](https://github.com/quay/clair/commit/d34acaf54063d04979820a6be6e8c0181fc0fb65): update for v4
### Httptransport
- [e1144aa](https://github.com/quay/clair/commit/e1144aaf0af143d63c59d1cfcc8f06490377c1d8): made discovery endpoint more Accepting
### Misc
- [18e4db2](https://github.com/quay/clair/commit/18e4db2c0298696797975911ff4c7b48f41b54fc): doc and commit check fixes
### Notifier
- [7d95067](https://github.com/quay/clair/commit/7d95067f4762ec1aa79879e23c7956eaef8ca4f7): remove first update constraint

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

<a name="v4.0.0-alpha.7"></a>
## [v4.0.0-alpha.7] - 2020-06-01
### Config
- [3ccc6e0](https://github.com/quay/clair/commit/3ccc6e03be0ce1b6c439d5c0649ee785dc7c559f): add support for per-scanner configuration
### Dockerfile
- [5a73cb4](https://github.com/quay/clair/commit/5a73cb49d64e839d7675979b5e3f348d94dd26a5): make -mod=vendor opportunistic ([#999](https://github.com/quay/clair/issues/999))
 -  [#999](https://github.com/quay/clair/issues/999)### Dockerfile: Update To Alpine
- [de32b07](https://github.com/quay/clair/commit/de32b0728ccdbafb85988e2f87618c9d576fc87e): 3.11 for newest rpm
### Go.Mod
- [badcac4](https://github.com/quay/clair/commit/badcac4420b44d92d1d56d5f9c9a09daf8a5db50): update yaml to v3
### Httptransport
- [54c6a6d](https://github.com/quay/clair/commit/54c6a6d46e6087690287c4b247668e954d6913af): document exposed API

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
### Config
- [2ed3c2c](https://github.com/quay/clair/commit/2ed3c2c800bb9639618a86f33916625b0a595f49): rework auth config
### Httptransport
- [5683018](https://github.com/quay/clair/commit/5683018f2e7d091897a238aa82e88da56941fee8): serve OpenAPI definition

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
- [33da12a](https://github.com/quay/clair/commit/33da12a3bb9a28fdbcc6302caa4212d38a2acbbb): run as unprivileged user by default
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
## v4.0.0-alpha.2 - 2020-03-26
### *
- [74efdf6](https://github.com/quay/clair/commit/74efdf6b51e3e625ca9f122e7aa88e88f4708a68): update roadmap
 - Fixes [#626](https://github.com/quay/clair/issues/626)- [ce15f73](https://github.com/quay/clair/commit/ce15f73501b758b3d24e06753ce62123d0a36920): gofmt -s
- [5caa821](https://github.com/quay/clair/commit/5caa821c80a4efa2986728d6f223552b44f6ce15): remove bzr dependency
- [033cae7](https://github.com/quay/clair/commit/033cae7d358b2f7b866da7d9be3367d902cdf035): regenerate bill of materials
- [1f5bc26](https://github.com/quay/clair/commit/1f5bc26320bc58676d88c096404a8503dca7a4d8): rename example config
- [d0ca4d1](https://github.com/quay/clair/commit/d0ca4d1fe6a4b28be5f2a82c640f8886551034fb): added bill-of-materials
- [324ad5f](https://github.com/quay/clair/commit/324ad5f2435d02a10211e3134fb3353aeb62c55d): move all references in README to HEAD
- [836d37b](https://github.com/quay/clair/commit/836d37b2758e5abcce1d85ee680bd5d0d65f0538): use `path/filepath` instead of `path`
- [51e4086](https://github.com/quay/clair/commit/51e4086298f6f17b5ad92cb6c021f16e80440d46): Create a ROADMAP
- [16a652f](https://github.com/quay/clair/commit/16a652fa4726a0e06492ce36eaae281c83ccd774): refresh godeps
- [f6baac3](https://github.com/quay/clair/commit/f6baac3628d89f00cd6bb4f28163a3d089b429df): refresh godeps
- [8f7e658](https://github.com/quay/clair/commit/8f7e6585746e756fac5ca2686e5c730977656f99): remove tests from docker file
- [1e1eb92](https://github.com/quay/clair/commit/1e1eb9218dc4e04cbe70bd6b4e22186cd0b820e2): add postgres 9.4 to travis
- [5fdd9d1](https://github.com/quay/clair/commit/5fdd9d1a07220ede12a7009b54641103fcfe2c24): add metadata support along with NVD CVSS
- [40a7c8a](https://github.com/quay/clair/commit/40a7c8a00d580d1a7db4f8bca2152bc5eb491c0a): refresh godeps
- [4bdbd5e](https://github.com/quay/clair/commit/4bdbd5e6db2e8e919938c3cb348350ba91966a12): fix several tests
- [b8b7be3](https://github.com/quay/clair/commit/b8b7be3f8127e0858c14eda0557ae51f2f897129): remove health checker
- [82175dc](https://github.com/quay/clair/commit/82175dcfe9e36766c5e88199d8045e2f0733f483): add missing copyright headers
- [2c150b0](https://github.com/quay/clair/commit/2c150b015e63d7ee5f45a6a875df8a14a2ac0b24): refactor & do initial work towards PostgreSQL implementation
- [8c1d3c9](https://github.com/quay/clair/commit/8c1d3c9a861d17d5b6ef59f5479192eb35b0a02b): Fix `authentification` typo
### .Github
- [9b1f205](https://github.com/quay/clair/commit/9b1f2058338b8aeaa5441091b4920731235f1353): add stale and issue template enforcement
### API
- [0151dba](https://github.com/quay/clair/commit/0151dbaef81cae54aa95dd8abf36d58414de2b26): change api port to api addr, rename RunV2 to Run.
 - Fixes [#446](https://github.com/quay/clair/issues/446)- [a378cb0](https://github.com/quay/clair/commit/a378cb070cb9ec56f363ec08adb8e023bfb3994e): drop v1 api, changed v2 api for Clair v3.
### All
- [fbbffcd](https://github.com/quay/clair/commit/fbbffcd2c2a34d8a6128a06a399234b444c74d09): add opentelemetry hooks
### Alpine
- [59e6c62](https://github.com/quay/clair/commit/59e6c628dcb2b4306ed971a609f7a50973ca2b2c): refactor fetcher & git pull on update
- [9be305d](https://github.com/quay/clair/commit/9be305d19f5fec286492cd09ed71623f356fcdc0): truncate namespace to "vMAJOR.MINOR"
- [f8457b9](https://github.com/quay/clair/commit/f8457b98e7dfe1c6fde7783c59a1c1143823a0e2): compile alpine into clair binary
- [3d90cac](https://github.com/quay/clair/commit/3d90cac427e52a6470f112746fa86a595ffe8717): add support for v3.4 YAML schema
### Api
- [69c0c84](https://github.com/quay/clair/commit/69c0c84348c74749cd1d12ee4e4959991621a59d): Rename detector type to DType
- [48427e9](https://github.com/quay/clair/commit/48427e9b8808f86929ffb905952395c91644f04e): Add detectors for RPC
- [dc6be5d](https://github.com/quay/clair/commit/dc6be5d1b073d87b2405d84d33f5bb5f6ced490e): remove handleShutdown func
- [30644fc](https://github.com/quay/clair/commit/30644fcc01df7748d8e2ae15c427f01702dd4e90): remove dependency on graceful
- [58022d9](https://github.com/quay/clair/commit/58022d97e3ec7194e89522c9adb866a85c704378): renamed V2 API to V3 API for consistency.
- [c6f0eaa](https://github.com/quay/clair/commit/c6f0eaa3c82197f15371b4d2c8af686d8a7a569f): fix remote addr shows reverse proxy addr problem
- [a4edf38](https://github.com/quay/clair/commit/a4edf385663b2e412e1fd64f7d45e1ee01749798): v2 api with gRPC and gRPC-gateway
 - Fixes [#98](https://github.com/quay/clair/issues/98)- [6a50bbb](https://github.com/quay/clair/commit/6a50bbb8b89cb78e38a9cb13b3cfc3fff277739c): fix 404 error logging
- [7aa8869](https://github.com/quay/clair/commit/7aa88690af4c85133519747e3633a458e6f44ba0): WriteHeader on health endpoint
 - Fixes [#141](https://github.com/quay/clair/issues/141)- [f14e4de](https://github.com/quay/clair/commit/f14e4de4d82d51f8dc41d55a782b2c4b535bae7e): fix anchor link in docs
- [3563cf9](https://github.com/quay/clair/commit/3563cf9061d80c52319d7814e0319c4c3689df95): fix pagination token that's returned to match what has been passed
- [274a162](https://github.com/quay/clair/commit/274a1620a50815149671368f1a1feda409830286): log instead of panic when a response could not be marshaled
- [8d76700](https://github.com/quay/clair/commit/8d767005063ebb285f6890500e35d0bab2174340): add call duration in logs
- [418ab08](https://github.com/quay/clair/commit/418ab08c4b248fe119a83179b25b6aef43070014): adjust postLayer error codes
- [f40f6a5](https://github.com/quay/clair/commit/f40f6a5ab6ebf4275be58c1b2e3a48c246f9df2e): add missing link field in vulnerability in getLayer
- [0e9a7e1](https://github.com/quay/clair/commit/0e9a7e174032e1304b367a30b689fbea91c59da4): close gzip writer to flush it
- [db974ae](https://github.com/quay/clair/commit/db974ae72205fb4f65ebad8a997ca686df658aef): fix postLayer response headers
- [6f02119](https://github.com/quay/clair/commit/6f02119c56182b53bc6d39eb67dff8e3501ebe34): add bad requests to insert layer
- [ca2b0cc](https://github.com/quay/clair/commit/ca2b0ccfcb336cb8440cc4d3c4071c30e61f36b0): support gzip responses
- [c7aa7c4](https://github.com/quay/clair/commit/c7aa7c4db4259d659e5c866ca3d0a61dd5cc247b): reorder constants and add comments
- [4516d6f](https://github.com/quay/clair/commit/4516d6fd73a9d69a4d041dc880f4bd5a00b4ad01): make postLayer returns a Layer
- [d19a434](https://github.com/quay/clair/commit/d19a4348dfdd0312d89857e2540e550b7f235fa9): implement fernet encryption of pagination tokens
- [b8c534c](https://github.com/quay/clair/commit/b8c534cd0da918626bc590d533874d20545a91a7): fix putVulnerability (fill missing Namespace.Name and Name fields)
- [c2061dc](https://github.com/quay/clair/commit/c2061dc69e7202a22affe8ab18513da17adc3f0e): fix negative timestamps in notifications
- [f68012d](https://github.com/quay/clair/commit/f68012de0031ca9df9292e69bd940147840079fb): fix 404->500 and NPE issues
- [c504d2e](https://github.com/quay/clair/commit/c504d2ed0e409ebc1a579259c8f8c80a3ba6e1a6): add FeatureFromDatabaseModel
- [f351d63](https://github.com/quay/clair/commit/f351d6304e91d5eced2161efdaddf57b662e7395): add "Content-Type" and "Server" headers
- [2d8d9ca](https://github.com/quay/clair/commit/2d8d9ca4010ec237a1dbd8fa56810180280df582): finish initial work on v1 API
- [b9a6da4](https://github.com/quay/clair/commit/b9a6da4a57698020d9e361e0b32acbf1b6de4f8c): implement delete notification
- [96e96d9](https://github.com/quay/clair/commit/96e96d948d226398df8c9e9662afe6ea47d262cf): handle last page for notifications
- [3eaae47](https://github.com/quay/clair/commit/3eaae478f9e8c2267c208bbbbd0c05029dcc7e53): implement get notification
- [116ce1a](https://github.com/quay/clair/commit/116ce1a806ca60aa50fbc1592b2118ab351d6b4d): fix log message when stopping the API server
- [c05848e](https://github.com/quay/clair/commit/c05848e32da7e2923d57d63d63fb131e2e611c0b): implement put vulnerability
- [8209922](https://github.com/quay/clair/commit/8209922c0c93992d484e9369e80d7981c5d6300c): implement delete vulnerability
- [dc99d45](https://github.com/quay/clair/commit/dc99d45f47392f833ad254cbccfb190b5fc5acdc): refactor endpoints and implement get vulnerability
- [6ac9b5e](https://github.com/quay/clair/commit/6ac9b5e6451abecb879ed63a446e051d206b6af6): fix graceful stop
- [9a8d4aa](https://github.com/quay/clair/commit/9a8d4aa591c6103531fc681ff03c6b1f89d85f4a): implement post vulnerability
- [38aeed4](https://github.com/quay/clair/commit/38aeed4f2c629ba79a7c176a74cdba3e0e0573dd): implement get namespaces route
- [b916fba](https://github.com/quay/clair/commit/b916fba4c6514d8c92f407c04873cec515b25d7d): implement delete layer route
- [04c7351](https://github.com/quay/clair/commit/04c7351911feb697712a77a8a06364709b448778): use pointers in models to get proper `omitempty` semantics
- [1a5aa88](https://github.com/quay/clair/commit/1a5aa88b18e74973c681b2937b2acb289167ceb8): use only one layer envelope
- [fa45d51](https://github.com/quay/clair/commit/fa45d516df5bbd46f622cc175f537d7dcee472da): add JSON tags to API models
- [d130d2f](https://github.com/quay/clair/commit/d130d2fab477964c0302218b9bb184b91a6056bf): implement getLayer
- [6b3f95d](https://github.com/quay/clair/commit/6b3f95dc0313268e36d9bee5d7ca6482049739e9): fix /v1 router and some status codes
- [be9423b](https://github.com/quay/clair/commit/be9423b489e4e694c35b187175aba10bb77012c8): add request / response types and rename some fields
- [822ac7a](https://github.com/quay/clair/commit/822ac7ab4c10f57463b3d2712f7ebedb26721354): add initial work on the new API
- [6e20993](https://github.com/quay/clair/commit/6e20993bac425bd14b86d5198f586ff8fc9a6b9c): simplify getLayer route and JSON output
- [e8b1617](https://github.com/quay/clair/commit/e8b16175effcff9b9ead13aeadab7897f5331d37): return 400 if we can't extract a layer
- [9946382](https://github.com/quay/clair/commit/9946382223431179b1133786bc6debfa1e288fee): Extracted client cert & HTTP JSON Render to utils.
- [9db0e63](https://github.com/quay/clair/commit/9db0e634011d6e805d3a542ab03cf2956b7d9734): Specify what packages cause the layer to have vulnerabilities.
### Api,Database
- [a75b8ac](https://github.com/quay/clair/commit/a75b8ac7ffe3ccd7ff9c4718e547c6c5103e9747): updated version_format documentation.
 - Fixes [#514](https://github.com/quay/clair/issues/514)### Api/Database
- [6d2eedf](https://github.com/quay/clair/commit/6d2eedf12131611b7be6c50dec04e9f55f363833): add the layer name that add each feature in getLayer
- [e444e93](https://github.com/quay/clair/commit/e444e93c975d977a5178351e41388c9d52d3872a): Add the ability to delete layers
### Api/Prometheus
- [83b19b6](https://github.com/quay/clair/commit/83b19b6179c663a11b8e6d0651397a5262a3fc3e): add prometheus metrics to API routes
### Api/V1
- [ebd0170](https://github.com/quay/clair/commit/ebd0170f5b5144d7ab5e4facf44eb99fe147fdc3): fix JSON struct tag misnomer
- [d4522e9](https://github.com/quay/clair/commit/d4522e9c6e3a6237863cc83d0f2fd1be74212613): indexed layers for notifications
- [68250f3](https://github.com/quay/clair/commit/68250f392b7820c30ee042a905ff9eb25860c186): create namespace type
 - Fixes [#99](https://github.com/quay/clair/issues/99)### Api/V3
- [32b11e5](https://github.com/quay/clair/commit/32b11e54eb287ed0d686ba72fe413b773b748a38): Add feature type to API feature
- [f550dd1](https://github.com/quay/clair/commit/f550dd16a01edc17de0e3c658c5f7bc25639a0a1): remove dependency on google empty message
- [d7a751e](https://github.com/quay/clair/commit/d7a751e0d4298442883fde30ee37c529b2bb3719): prototool format
### Api/V3/Clairpb
- [6b9f668](https://github.com/quay/clair/commit/6b9f668ea0b657526b35008f8efd9c8f0a46df9b): document and regenerate protos
- [ec5014f](https://github.com/quay/clair/commit/ec5014f8a13605458faf1894bb905f2123ded0a7): regen protobufs
- [389b6e9](https://github.com/quay/clair/commit/389b6e992790f6e28b77ca5979c0589e43dbe40a): generate protobufs in docker
### Api/Worker
- [53e6257](https://github.com/quay/clair/commit/53e62577bc9adc0f002f97fc87bdf9387e3ee663): s/Authorization/Headers ([#167](https://github.com/quay/clair/issues/167))
 -  [#167](https://github.com/quay/clair/issues/167)- [9b5afc7](https://github.com/quay/clair/commit/9b5afc79cab103721a599d65c45825d1faed766d): introduce optional authorization
- [e78d076](https://github.com/quay/clair/commit/e78d076d02343f2d3d167e3e5f96364c3837fec0): adjust error codes in postLayer
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
- [8896152](https://github.com/quay/clair/commit/889615276af2c1d5ac04971a237e09d2e9fa6bda): move worker to top level package
- [e5c567f](https://github.com/quay/clair/commit/e5c567f3f98b68d990e2b41c3a7f1f0261dcf060): mv notifier to top level
- [9c63a63](https://github.com/quay/clair/commit/9c63a639440d5669bbc318f85aa672d4ce9fa10f): mv updater clair and mv severity to db
- [343e24e](https://github.com/quay/clair/commit/343e24eb7eb6336dca94df7b43499dfef08ee4fe): remove `types` package
- [19e9d12](https://github.com/quay/clair/commit/19e9d1234ee2f001c01b688fd9dde84498b23df3): catch both SIGINT and SIGTERM for graceful shutdown
### Clair Logic, Extensions
- [fb32dcf](https://github.com/quay/clair/commit/fb32dcfa58077dadd8bfbf338c4aa342d5e9ef85): updated mock tests, extensions, basic logic
### Clairctl
- [f1c4798](https://github.com/quay/clair/commit/f1c4798bb10292fe1f14d71691ab33d4ea5a2ae9): start on clair cli tool
### Cmd
- [0342a2a](https://github.com/quay/clair/commit/0342a2a3e5d077d50127ee6bbcee21d4260a29be): make pagination key error clearer
### Cmd/Clair
- [b20482e](https://github.com/quay/clair/commit/b20482e0aebcf2cc67f61e8ff821ddcdffc53ac7): document constants
- [09dda9b](https://github.com/quay/clair/commit/09dda9bfd72b2c87ecd40578114f0ad452599db4): fix pprof
### Config
- [4f23269](https://github.com/quay/clair/commit/4f232698b0178ef9d1a3cde01b6ff40e47659cfa): add updaters and tracing options
- [162e8cd](https://github.com/quay/clair/commit/162e8cdafc66be28b021f83da736a2b612ddda99): enable suse updater
- [0609ed9](https://github.com/quay/clair/commit/0609ed964b0673806462a24147e6028da85d8a38): removed worker config
- [af2c688](https://github.com/quay/clair/commit/af2c68863482ae9f93a2db1533be260468a6ea2d): not properly loaded error ([#140](https://github.com/quay/clair/issues/140))
 -  [#140](https://github.com/quay/clair/issues/140) - fixes [#134](https://github.com/quay/clair/issues/134)- [30055af](https://github.com/quay/clair/commit/30055af03e357b44cfbacb3088eab337a94e51e8): failover correctly to default config
- [20af787](https://github.com/quay/clair/commit/20af78743774b18795cbf5210cc97cc172b1880d): fix default fallback
- [4fc32d2](https://github.com/quay/clair/commit/4fc32d22713a47eabf5b12b81897fdd34d59935b): add top-level YAML namespace 'clair'
 - Fixes [#95](https://github.com/quay/clair/issues/95)- [bb7745f](https://github.com/quay/clair/commit/bb7745f3fe21e85b5fe37919e11d6d121e08b9a1): better document example
### Contrib
- [76b9f8e](https://github.com/quay/clair/commit/76b9f8ea05b110d1ff659964fc9126824ec28b17): replace old k8s manifests with helm
- [ac1cdd0](https://github.com/quay/clair/commit/ac1cdd03c9e31ddaea627e076704f38a0d4719fb): move grafana and compose here
- [5540d02](https://github.com/quay/clair/commit/5540d02bc225a240ebc1b04cc83c1adae680da39): delete unsupported tools
- [f3840f3](https://github.com/quay/clair/commit/f3840f30b9228319751435fee5ed9a25202aa4ab): Revert "Merge pull request [#367](https://github.com/quay/clair/issues/367) from jzelinskie/analyze-layers-v2"
 -  [#367](https://github.com/quay/clair/issues/367)- [e772be5](https://github.com/quay/clair/commit/e772be5f6f75af54bff1c2febd3c863308d53956): only extract layers from history
- [ff3c6ec](https://github.com/quay/clair/commit/ff3c6eccc849c7bce27e872e59584e646081b02c): Catch signals to delete tmp folder in local-analyze-images
- [55e9c0d](https://github.com/quay/clair/commit/55e9c0d8547e7dbd03da09fd17c1f68f17cac092): Fix dead link from analyze-local-images' README
- [1040dbb](https://github.com/quay/clair/commit/1040dbbff9ea395700d1232b4906b73e0de32a8f): Use `return` instead of `os.Exit(1)` in analyze-local-images
 - Fixes [#117](https://github.com/quay/clair/issues/117)- [251df95](https://github.com/quay/clair/commit/251df954ce2aadadd0fb5060bb2458480f3358b4): Add a ability to force colored output in analyze-local-images
- [f024576](https://github.com/quay/clair/commit/f024576223c5b4a1a06207f2e756f62e160ea99b): Add vendors to analyze-local-images
- [80ddc7f](https://github.com/quay/clair/commit/80ddc7f949f31abcf0130c3886af8ef72bb72127): Pretty up analyze-local-images
- [e341710](https://github.com/quay/clair/commit/e34171025d61a6272036e770989167716042256d): Add colors / Modify spacing in the analyze-local-images's output
- [93ffc5a](https://github.com/quay/clair/commit/93ffc5a1e5052bba2b7ddeb28b2414e6025c8b3d): Show feature line only if there's a vuln in analyze-local-images
- [910288f](https://github.com/quay/clair/commit/910288fc97ff26d8aac2b96ada85a6f79a1069e6): Add minimum severity support to analyze-local-images
- [001c0a7](https://github.com/quay/clair/commit/001c0a73d3c186feb7932c47fd8e99212319a6b2): adapt analyze-local-images for new API
- [fee0bb5](https://github.com/quay/clair/commit/fee0bb5e495df241594419977750e00159d4b460): load image history from 'manifest.json' first due to docker 1.10 changes.
 - Fixes [#69](https://github.com/quay/clair/issues/69)- [75aff03](https://github.com/quay/clair/commit/75aff0382a567a29ef12d5003e8f8d7cbba092bf): check-openvz-mirror-with-clair fix license
- [8b137e8](https://github.com/quay/clair/commit/8b137e8a95a1755aacd3e97b707c647f96a9c3ac): add copyright in check-openvz-mirror-with-clair
- [7df8e7f](https://github.com/quay/clair/commit/7df8e7fb1a3c1de4fe3998ffa9a34fa607e05e5e): add copyright in analyze-local-images
- [867279a](https://github.com/quay/clair/commit/867279a5c9589885743f0157d26a23e44227a69a): Improve analyze-local-images docs and launch command.
 - Fixes [#32](https://github.com/quay/clair/issues/32)- [9391417](https://github.com/quay/clair/commit/9391417b2d2761918c1a6f6f165fe1a35275cfb7): Wait for extraction to finish before continuing.
- [8d071e2](https://github.com/quay/clair/commit/8d071e28ffb445030d358b12030a5928477052bd): Don't pass -z to tar in analyze-local-images
- [46f7645](https://github.com/quay/clair/commit/46f7645a53772310cbbacab8bd6aba8ae91fe63e): Add a tool to analyze local Docker images
### Contrib/Analyze-Local-Images
- [e103528](https://github.com/quay/clair/commit/e10352864da16a7484fa445c2bba07998123e153): use exit(1) when there are vulnerabilities
### Contrib/Helm/Clair
- [13be17a](https://github.com/quay/clair/commit/13be17a69082d30996d53d3087b7265007bae555): fix the ingress template
### Contrib: Add Missing 
- [d76c549](https://github.com/quay/clair/commit/d76c549dfb18267ce72bd4e1e2fcb18f0d3bdc1a): =
 -  [#367](https://github.com/quay/clair/issues/367) - Fixes [#368](https://github.com/quay/clair/issues/368)### Convert
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
- [b99e2b5](https://github.com/quay/clair/commit/b99e2b50e27e1b882c7aac4fc0c02e7b561dafce): Add some missing copyright headers
- [629d2ce](https://github.com/quay/clair/commit/629d2ce662c5e81628982b1b4f81ef15aa04fae7): Mock Datastore interface
- [e7b960c](https://github.com/quay/clair/commit/e7b960c05b19d3bca0e1027071cacbbcf131c1a5): Allow specifying datastore driver by config
 - Fixes [#145](https://github.com/quay/clair/issues/145)- [79ba99b](https://github.com/quay/clair/commit/79ba99bbea9c8d4b13b96e4a53b37068007e44e7): Fix invalid error message
- [9b191fb](https://github.com/quay/clair/commit/9b191fb598ab9b227180202603b5c3182d562686): Find the FeatureVersion we try to insert before doing any lock
- [8431950](https://github.com/quay/clair/commit/84319507df7ca69aa5d8311fd2d8431041b1c2e4): use constants to store queries
- [06531e0](https://github.com/quay/clair/commit/06531e01c5d195fdf5a0865fdcd423d03be06fd5): disable hash/merge joins in FindLayer
- [18f2d7e](https://github.com/quay/clair/commit/18f2d7e672d99091414a14ff3a80ac97f73e03d0): modify join table in FindLayer to reduce cost by 3.5x
- [b5d8f99](https://github.com/quay/clair/commit/b5d8f9952e2d89444ec286fab7a077cedc73b8fd): fix notification test (wrong signature)
- [f0816d2](https://github.com/quay/clair/commit/f0816d2c4dd92e10fe8e0713fb7890da1e306c0f): add docs about the interface
- [d3b1410](https://github.com/quay/clair/commit/d3b14106a9c1ba4855b94bcb5cfef37028706d83): ignore insertLayer collisions to make it truly idempotent
- [e3a25e5](https://github.com/quay/clair/commit/e3a25e53680fe01c8166ef0f1dd0a4ff3fda5f85): ignore min versions during new vulnerability insertions
- [883be87](https://github.com/quay/clair/commit/883be8769f06ce2eebc70e8c3416376bbc05ce44): fix Ping() method in PostgreSQL's implementation
- [f8b4a52](https://github.com/quay/clair/commit/f8b4a52f8a4c02629184d5fe3c12ee4962f5af31): make notification tests more robust (old/new, update/delete vulnerabilities)
- [ccaaff0](https://github.com/quay/clair/commit/ccaaff000e42adc71149b56dfcd3d4a740d4b830): add created_at field for layers and vulnerabilities
- [94ece7b](https://github.com/quay/clair/commit/94ece7bf2b5a26e6b99fd0dbafe5f04580100196): fix notification design and add vulnerability history
- [99f3552](https://github.com/quay/clair/commit/99f35524709119eced2e482a35f91af052e21916): add Insert/DeleteVulnerabilityFix
- [03d904c](https://github.com/quay/clair/commit/03d904c6206da4f868c0c5f52cd96cd6f812e28a): improve PostgreSQL test inits and cleanups
- [8f9779e](https://github.com/quay/clair/commit/8f9779e232193787ab60263d67a555cf3a8ab811): cache feature version upon lookup
- [1e4ded6](https://github.com/quay/clair/commit/1e4ded6f2b314fe4b61b3b6613b53923bfcacb69): add ability to list namespaces
- [35df7ca](https://github.com/quay/clair/commit/35df7ca0eb3529f458aa4c7436149045a0d7df97): fix feature version cache
- [8be18a0](https://github.com/quay/clair/commit/8be18a0a01e8733fd7a841645eecc04143949833): write more of the notification system
- [d3d689a](https://github.com/quay/clair/commit/d3d689a26ae89a700ff6fcdc1c3fefea345d297d): don't prune locks when we renew one
- [2690800](https://github.com/quay/clair/commit/26908003314498c899545bf73319f274fb9071b5): create notification during vulnerability insertion
- [63ebddf](https://github.com/quay/clair/commit/63ebddfd3662c6a208c5960b64a13ed6e86dd6f6): add vulnerability deletion support
- [21f152c](https://github.com/quay/clair/commit/21f152c03e8d5274d60889d2faf0bba77034958a): fix keyvalue/notification tests
- [563b382](https://github.com/quay/clair/commit/563b3825d8702b34390223a3a96e86d5ff651c18): let handleErrors deal with the not found case
- [5759af5](https://github.com/quay/clair/commit/5759af5bcff60d1163f4995d8182402eff19ba8f): test and fix layer updates
- [248fc7d](https://github.com/quay/clair/commit/248fc7df7226a02169d32f8d8e5d4709b82377c9): fix cache collision (feature & feature versions)
- [92b734d](https://github.com/quay/clair/commit/92b734d0a44fece5657e548a1fb65d7bf93ab7bb): remove an useless query in FindLayer
- [bd17dfb](https://github.com/quay/clair/commit/bd17dfb5e11b927e7134998286aff8511e83e954): ensure that concurrent vulnerability/feature versions insertions work fine
- [74fc5b3](https://github.com/quay/clair/commit/74fc5b3e66dc81f2079f6d0d730491ff7b30a2c7): add missing transaction commits and close opened statement before inserting feature versions.
- [c5d1a8e](https://github.com/quay/clair/commit/c5d1a8e5f78f3774f4cb895aa901d6bc780719df): update vulnerabilities only when necessary
- [1b53142](https://github.com/quay/clair/commit/1b53142e3808942d9a871192e464a6bb10dd3ddb): allow removing fixed packages in vulnerabilities
- [7c70fc1](https://github.com/quay/clair/commit/7c70fc1c205caa45926ae1435d74d162abf13d54): add initial vulnerability support
- [3a786ae](https://github.com/quay/clair/commit/3a786ae020d6e0a07c2b7b1d572070afc242634a): add lock support
- [6a9cf21](https://github.com/quay/clair/commit/6a9cf21fd4a8e5e04426e5f0c28b7ccac3e10823): log and mask SQL errors
- [970756c](https://github.com/quay/clair/commit/970756cd5a8364b4912f99859c7626d4db7f97b6): do insert/find layers (with their features and vulnerabilities)
- [32747a5](https://github.com/quay/clair/commit/32747a5f250bc5bfac41c5754bbe49efde7bb847): Don't ignore empty results in toValue(s)()
- [3fe3f3a](https://github.com/quay/clair/commit/3fe3f3a4c74568699d0cbbeb9abdb28d1f249c21): Update cayley and use Triple instead of Quad
- [9fc29e2](https://github.com/quay/clair/commit/9fc29e291c60a0f244cca91372ba6044bb670838): put missing predicates in consts and un-expose some of them
 - Fixes [#16](https://github.com/quay/clair/issues/16)- [8285c56](https://github.com/quay/clair/commit/8285c567c811de952d30ef0583db42237600b2f0): Improve InsertVulnerabilities.
- [cfa960d](https://github.com/quay/clair/commit/cfa960d61903887c203af8d0a3d204a4fe0b7fb0): Update Cayley to fix slow deletions
- [915903c](https://github.com/quay/clair/commit/915903c1c151df563204f76038f77df578d64cd4): Fix to a locking issue with PostgreSQL
- [8aacc8b](https://github.com/quay/clair/commit/8aacc8bfdcf72bd607bb491ce2533c5c0ef2313e): Ensure that quads in a tx are applied in the desired order.
- [3a1d060](https://github.com/quay/clair/commit/3a1d0602fb7006dceb99f4697bbee02ad5ffaa93): Use an estimator in Cayley's Size() w/ PostgreSQL
- [b0142e1](https://github.com/quay/clair/commit/b0142e1982ebec8226b1f4c8622a49f52b8adba2): reduce pruneLocks/Unlock transaction.
- [7f1ff8f](https://github.com/quay/clair/commit/7f1ff8f97908d092bc73388ee910e8c0fdbda096): reduce InsertPackages transaction
### Database/Api
- [726bd3c](https://github.com/quay/clair/commit/726bd3c0c60522fd3fa56b0e5a79494afed2c186): add layer deletion support
### Database/Models
- [0305dde](https://github.com/quay/clair/commit/0305dde964e5f21a84087b55d7c6899107543b4b): MetadataMap decodes from string
### Database/Pgsql
- [4491bed](https://github.com/quay/clair/commit/4491bedf2e284007fa7f527bf264dc98c937d820): move token lib
- [9e875f7](https://github.com/quay/clair/commit/9e875f748dd218ac0d3bdb4a11bc3830cee5c8be): copy whole namespace
### Database/Worker
- [f229083](https://github.com/quay/clair/commit/f229083e1e52d2fea46cb7c69be05b5e5f32c680): Remove useless log message
### Datastore
- [57b146d](https://github.com/quay/clair/commit/57b146d0d808a29db9f299778fb5527cd0974b06): updated for Clair V3, decoupled interfaces and models
### Db/Pgsql/Feature
- [627b98e](https://github.com/quay/clair/commit/627b98ef3126d517d3e80aef4c2ab9ed3d14b893): fix SQL error reporting
### Db/Pgsql/Migration
- [8df8170](https://github.com/quay/clair/commit/8df8170ba54d945cf2e2ad201bcdb8cc09fddc06): convert to pure SQL
### Dockerfile
- [80f150f](https://github.com/quay/clair/commit/80f150f93bf3b12e6c9bcea2d71ccfa956bd50c9): Add docker-compose.yml
### Detectors/Feature
- [fc908e6](https://github.com/quay/clair/commit/fc908e65ba6c0ad3edb344cfb263adff8efe6f4e): add apk feature detector
- [e4b5930](https://github.com/quay/clair/commit/e4b5930f7769083767005d8e1730be81bf9eab8f): consistent naming and godoc
### Detectors/Namespace
- [1d5a9dd](https://github.com/quay/clair/commit/1d5a9ddd3c2849ecd0346b55212c73a616b1382d): add alpine-release detector
- [0b2a9ab](https://github.com/quay/clair/commit/0b2a9ab12b1f6e1308cad933bb7ad6cf15017011): support pointers in tests
### Dockerfile
- [2ca92d0](https://github.com/quay/clair/commit/2ca92d00754b1d1859e9d6f3169d67d6b96d6bee): bump Go to 1.13
- [c1e0f61](https://github.com/quay/clair/commit/c1e0f618caad4464d90ba20e13baaa1fb1617cb9): add git dependency
- [8918f40](https://github.com/quay/clair/commit/8918f40599685c5781d5b6b53ec99120bedc65f4): update deps and move to Go 1.6
- [ea193d3](https://github.com/quay/clair/commit/ea193d3ae72a3a52e56289dceebf1fbda9949c4c): syntax updates and s/xz/xz-utils
### Dockerfile
- [e56b95a](https://github.com/quay/clair/commit/e56b95aca0085067f91f90e3b32dab9d04e7fb48): use environment variables
- [33b3224](https://github.com/quay/clair/commit/33b3224df13b9c2aa8b0281f120997abce82eaf9): update for clair v4
- [df4f277](https://github.com/quay/clair/commit/df4f277d0e36405dc2e607730097464dfd45c1f3): use alpine linux 3.5 (bis)
- [4721e92](https://github.com/quay/clair/commit/4721e92b17d96f7a229112288f25d2a03c741ef7): use alpine linux 3.5
- [6b23520](https://github.com/quay/clair/commit/6b23520710396877e941611f62f4e12fa002db99): remove useless volume
### Docs
- [49b5621](https://github.com/quay/clair/commit/49b5621d738978c94e8d311775bba48a1daafc7e): fix typo in running-clair
- [9ee2ff4](https://github.com/quay/clair/commit/9ee2ff4877db15a5ad8ae24afcb8f02f0e8289cf): add troubleshooting about kernel packages
- [3f91bd2](https://github.com/quay/clair/commit/3f91bd2a9bc40bd7b6f4e5a5a8a533de383f3554): turn README into full articles
- [821a608](https://github.com/quay/clair/commit/821a608bb1ad7336bc817ef5ef4ded3b8ddb2ed9): add links to contrib tools
- [6e8e6ad](https://github.com/quay/clair/commit/6e8e6ad26b0d6ce7a9c34dde7a7c80926aae3a48): fix broken link
- [107582c](https://github.com/quay/clair/commit/107582c96e59b67959811ea8b99d17e512fcc2a7): Correct docker-compose command
- [12c47e4](https://github.com/quay/clair/commit/12c47e406608c72bf481dfe403863f7ae05ffb2b): split http and json code blocks
- [37a5826](https://github.com/quay/clair/commit/37a58260db3f4b269edb7d0785fb8cce34969b74): improve GET/POST /v1/layers documentation
- [859b194](https://github.com/quay/clair/commit/859b1942a5872faed16101277479ea7796033442): fix the docker cli of running clair in README.md
- [fd6fdbd](https://github.com/quay/clair/commit/fd6fdbd3f9de119e9528f836f6d67bd951af3586): update config example
- [9329172](https://github.com/quay/clair/commit/93291726839994651ba981d9d85efef04807602a): provide information to run Clair in README
- [7b608ce](https://github.com/quay/clair/commit/7b608ceda50be838a801a40c00012e26a32bffc2): Add missing field in API Example
- [ec0decf](https://github.com/quay/clair/commit/ec0decfcafd32edc9212ed7c1a94e96df10924d6): fix a typo in the model
 - Fixes [#43](https://github.com/quay/clair/issues/43)### Documentation
- [3e6896c](https://github.com/quay/clair/commit/3e6896c6a4e5cdd04d91927d762b332b62e1d4fe): fix links to presentations
 - Closes [#661](https://github.com/quay/clair/issues/661) - Closes [#665](https://github.com/quay/clair/issues/665) - Closes [#560](https://github.com/quay/clair/issues/560)### Documentation
- [c1a58bf](https://github.com/quay/clair/commit/c1a58bf9224bbcd7e0f02ea4065650d220654f29): add new 3rd party tool
### Driver
- [5c58575](https://github.com/quay/clair/commit/5c5857548d43fa866d46a4c98309b2dfa88be418): Add proxy support
### Drone
- [0fd9cd3](https://github.com/quay/clair/commit/0fd9cd3b59bd42ef0e508f0f415028a0ee8fa44f): remove broken drone CI
- [352f738](https://github.com/quay/clair/commit/352f73834e7bdef31dc5e3a715133f5c47947764): init
### Example Config
- [8d10d93](https://github.com/quay/clair/commit/8d10d93b177490139ec1f9ce417a9a8acfb3b1b6): add localhost postgres
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
- [cda3d48](https://github.com/quay/clair/commit/cda3d4819c261932ad24196f51f4a4b4fec022bd): feature detector -> featurefmt
- [71a8b54](https://github.com/quay/clair/commit/71a8b542f95cf34746d1b544a0fe1790a9f6eb09): misc doc comment fixes
- [fb193e1](https://github.com/quay/clair/commit/fb193e1fdecad209e17a890e6727d04931015e0b): namespace detector -> featurens
- [d9be34c](https://github.com/quay/clair/commit/d9be34c3c4cf7a8d1865abd064c59dd3f24f51bd): data detector -> imagefmt
- [f9b3190](https://github.com/quay/clair/commit/f9b319089d4d5b0dfd64c6f80fc4117657270b77): lock all drivers
### Ext/Featurefmt
- [1c40e7d](https://github.com/quay/clair/commit/1c40e7d01697f5680408f138e6974266c6530cb1): Refactor featurefmt testing code
### Ext/Featurefmt/Apk
- [2cc61f9](https://github.com/quay/clair/commit/2cc61f9fc0edc42d2c0fda71471208e3faba507d): Extract origin package information from database
- [b2f2b2c](https://github.com/quay/clair/commit/b2f2b2c854b4e3e15e53616ca221f7953bdc38eb): handle malformed packages
### Ext/Featurefmt/Dpkg
- [4ac0466](https://github.com/quay/clair/commit/4ac046642ffea9fb60af455b9d22d19cd4408f32): Extract source package metadata
- [590e7e2](https://github.com/quay/clair/commit/590e7e2602526dd5ae1c08436ab98b299e3cd69d): handle malformed packages
### Ext/Featurefmt/Rpm
- [a057e4a](https://github.com/quay/clair/commit/a057e4a943dc1a2dc1898b67435b05417725402e): Extract source package from rpm database
### Ext/Featurens
- [34bc722](https://github.com/quay/clair/commit/34bc722794291da77c9917155fbbc31a7001baf4): add empty filesmap tests for all
- [03b8cd9](https://github.com/quay/clair/commit/03b8cd9a4584db0ca18032bf109469ceb2adc3d3): add missing lock
### Ext/Vulnsrc/Alpine
- [0891bba](https://github.com/quay/clair/commit/0891bbac00c9e0bbed159bcdd438edcb42331954): use HTTPS
### Ext/Vulnsrc/Oracle
- [09cbfe3](https://github.com/quay/clair/commit/09cbfe325b93f19aa05a946ab90d76296d2bd2f4): ensure flag is largest elsa
- [bcf47f5](https://github.com/quay/clair/commit/bcf47f53ee704892483f4d3b1c29f306b1eb6dcf): fix ELSA version comparison
### Ext/Vulnsrc/Rhel
- [d606d85](https://github.com/quay/clair/commit/d606d85afeed37df5f2806325fd6f4eae03be5ac): fix logging namespace
### Ext/Vulnsrc/Ubuntu
- [300fe98](https://github.com/quay/clair/commit/300fe980ef44134d23b21afd643fa9336210c0f2): add missing version format
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
### Fetchers/Alpine
- [f74cd35](https://github.com/quay/clair/commit/f74cd352438a710d51f56b9f3a32b77cc403fe32): add notes for untracked namespaces
- [3be8dfc](https://github.com/quay/clair/commit/3be8dfcf99dfde8aaf67c60eb279c17b8a7e83d2): auto detect namespaces
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
- [d846c50](https://github.com/quay/clair/commit/d846c508c3aecf52d4e5aa3d47591614e50aa4e7): refresh dependencies
### Go.Mod
- [ad58dd9](https://github.com/quay/clair/commit/ad58dd9758726e488b5c60a47b602f1492de7204): update to latest claircore
### Godeps
- [213468a](https://github.com/quay/clair/commit/213468a6d58787a7c52ecaea97d60412ae02965d): Remove implicit git submodules
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
 - Fixes [#581](https://github.com/quay/clair/issues/581)### Imagefmt
- [891ce16](https://github.com/quay/clair/commit/891ce1697d0e53e253001d0ae7620f31b886618c): Move layer blob download logic to blob.go
### Indexer
- [500355b](https://github.com/quay/clair/commit/500355b53c213193147e653b147afc3036ea2125): add basic latency summary
- [8953724](https://github.com/quay/clair/commit/8953724bab392fa3897c2fae62b5df6e9567047c): QoL changes to headers
- [741fc2c](https://github.com/quay/clair/commit/741fc2c4bacb7e5651b05b298257a41ec7558858): HTTP correctness changes
- [10d2f54](https://github.com/quay/clair/commit/10d2f5472efc414846b56edf9d77a69246ea06b2): rename index endpoint
- [ac0a0d4](https://github.com/quay/clair/commit/ac0a0d49424f1f19b5044ea84a245e3139b5adb3): add Accept-Encoding aware middleware
- [3a9ca8e](https://github.com/quay/clair/commit/3a9ca8e57a041bdd78d5e37a904a1ff5942befd8): add State method
### Integrations
- [a5b92fe](https://github.com/quay/clair/commit/a5b92feb46dd12244672ed2ddf27350046ae2c1d): add quay enterprise as well
### Layer
- [015a79f](https://github.com/quay/clair/commit/015a79fd5a077a3e8340f8cef8610512f53ef053): replace arrays with slices
### Main
- [7ca9127](https://github.com/quay/clair/commit/7ca9127bbec404b9e2edbb5919a610dc0ac6a4fc): default config to /etc/clair/config.yml
- [eb7e5d5](https://github.com/quay/clair/commit/eb7e5d5c742afb26963b6ef2f3fe2712b9d76ce4): Use configuration file instead of flags and simplify app extension.
### Mapping
- [07a08a4](https://github.com/quay/clair/commit/07a08a4f53cab155814eadde44a847e2389b5bcc): add ubuntu mapping
 - Fixes [#552](https://github.com/quay/clair/issues/552)### Matcher
- [15c098c](https://github.com/quay/clair/commit/15c098c48cac6e87b82a4af4b5914aef0ab83310): add basic latency summary
- [0017946](https://github.com/quay/clair/commit/0017946470397c252b1934d1637fe7b1d01fe280): return OK instead of Created
### Namespace
- [c28d2b3](https://github.com/quay/clair/commit/c28d2b3a66cbd468f567ed0b4ddce3157169707d): add debug output
### New API
- [a541e96](https://github.com/quay/clair/commit/a541e964e07ea0e9a70f2ebee68897edf852bcba): list vulnerabilities by namespace
### Notifier
- [927af43](https://github.com/quay/clair/commit/927af43be074584546c3ece5d0cf4c91d8389669): Verify that the given webhook endpoint is an absolute URL
- [2fb815d](https://github.com/quay/clair/commit/2fb815dc3716f297870f63e3624eb473bfa3ddda): Add proxy parameter to webhook notifier
- [136b907](https://github.com/quay/clair/commit/136b907050e0686e60ae8cbcd51ec67ab4627063): add README
- [904ce60](https://github.com/quay/clair/commit/904ce6004f09f1b8db376b20caff6246e8561e8b): add a timeout on the http client
- [4478f40](https://github.com/quay/clair/commit/4478f40ef19e3c3a067ca166ce7ab3e7218de6df): fix notifier error handling and improve web hook error message
- [f4a4d41](https://github.com/quay/clair/commit/f4a4d417e7fee46add6f32d6284a9a6a8b9ce10d): Rename HTTP to Webhook Notifier
- [2ea86c5](https://github.com/quay/clair/commit/2ea86c53f3e32b5e2781bd5b087d3123a8e61e6c): fix a bug that prevented graceful shutdown in certain cases
- [480589a](https://github.com/quay/clair/commit/480589a83abfa6c9249771d535c2a405c7ce3466): retry upon failure
- [3ff8bfa](https://github.com/quay/clair/commit/3ff8bfaa9311ca5923809b89b92299eed558be2c): Allow custom notifiers to be registered.
- [b3828c9](https://github.com/quay/clair/commit/b3828c9c4c622891426da8a65f1de471fdd3ecbe): add ServerName configuration for TLS
- [20a126c](https://github.com/quay/clair/commit/20a126c84ae8fad5f9a9ee3bc042866407d48308): Refactor and add client certificate authentification support.
 - Fixes [#23](https://github.com/quay/clair/issues/23)### Notifier/Database
- [ad0531a](https://github.com/quay/clair/commit/ad0531acc7614cf6fa68d9ce7c66ff293832dfcf): refactor notification system and add initial Prometheus support
- [c60d005](https://github.com/quay/clair/commit/c60d0054fa0f11dac76547f30f2bd25410d4bf9f): draft new notification system
### Nvd
- [e953a25](https://github.com/quay/clair/commit/e953a259b008042d733a4c0aadc9b85d1bedf251): fix the name of a field
### Openapi
- [1949ec3](https://github.com/quay/clair/commit/1949ec3a22a5d2dd5cc30a5fccb99c49a657677a): lint and update Layer
### Osrelease-Detector
- [d88f797](https://github.com/quay/clair/commit/d88f7978213d1b21ea7c3bd4d1466f35dc2784e4): avoid colliding with other detectors
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
- [ca9f340](https://github.com/quay/clair/commit/ca9f340a91eaca32af143349d14e9a9639801938): only select distinct layers
- [ea73aa1](https://github.com/quay/clair/commit/ea73aa153d8b266096e37be3c87f3d0b045f31a5): searchNotificationLayerIntroducingVulnerability order by layer ID
- [7a3dd5c](https://github.com/quay/clair/commit/7a3dd5c817ae9f53917a1f7a87380f148fda4ec4): Disable hashjoins to get introducing layers for notifications
- [dc8f710](https://github.com/quay/clair/commit/dc8f71024f0340db55d4b3dd3675e9bdce0c53f2): Reduce cost of GetNotification by 2.5
- [ec0aad9](https://github.com/quay/clair/commit/ec0aad9b7a4e8021b633f983f2e1d9ef496bf49c): Use booleans instead of varchar to return creation status
- [cd23262](https://github.com/quay/clair/commit/cd23262e41fc51eefe6aad403f777a21df93bb22): Do not insert entry in Vulnerability_FixedIn_Feature if existing
 - Fixes [#238](https://github.com/quay/clair/issues/238)- [b8865b2](https://github.com/quay/clair/commit/b8865b21061a5801ada688fe06ce8745e94f0093): Replace liamstask/goose by remind101/migrate
 - Fixes [#93](https://github.com/quay/clair/issues/93)- [5d8336a](https://github.com/quay/clair/commit/5d8336acb342cc022c912f8f37045ace62f3c84a): use subquery to plan GetNotification query ([#182](https://github.com/quay/clair/issues/182))
 -  [#182](https://github.com/quay/clair/issues/182)- [51f9c5d](https://github.com/quay/clair/commit/51f9c5dcb430dab8907df425521ee650d5a4fb45): remove unnecessary join used in GetNotification ([#179](https://github.com/quay/clair/issues/179))
 -  [#179](https://github.com/quay/clair/issues/179)### Pgsql/Migrations
- [224ff82](https://github.com/quay/clair/commit/224ff825434ebdb907a2276ef4577b69e3d49808): fix dpkg default versionfmt
- [eeb13a0](https://github.com/quay/clair/commit/eeb13a02baa5db60b997454af8f059a6381f42da): add index on Vulnerability_Notification.deleted_at
- [7cff31a](https://github.com/quay/clair/commit/7cff31a058230a94838b7fd8493380d444c31f5a): add ldfv compound index
### Pkg
- [c3904c9](https://github.com/quay/clair/commit/c3904c9696bddc20a27db9b4142ae704350bbe3f): Add fsutil to contain file system utility functions
- [78cef02](https://github.com/quay/clair/commit/78cef02fdad4afd12a2a00df51d457c796278bfa): cerrors -> commonerr
- [03bac0f](https://github.com/quay/clair/commit/03bac0f1b6f504a416937e309a62fdfc308dc397): utils/tar.go -> pkg/tarutil
### Pkg/Gitutil
- [c2d887f](https://github.com/quay/clair/commit/c2d887f9e99184af502aca7abbe2044d2929e789): init
### Pkg/Grpcutil
- [c4a3254](https://github.com/quay/clair/commit/c4a32543e85a46a94012cfd03fc199854ccf3b44): use cockroachdb cipher suite
- [1ec2759](https://github.com/quay/clair/commit/1ec2759550d6a6bcae7c7252c8718b783426c653): init
### Pkg/Pagination
- [0565938](https://github.com/quay/clair/commit/05659389569549f445eefac650df260ab4f4f05b): add token type
- [d193b46](https://github.com/quay/clair/commit/d193b46449a64a554c3b54dd637a371769bfe195): init
### Pkg/Stopper
- [00e4f70](https://github.com/quay/clair/commit/00e4f7097241574277d4ed77d4c017f0c158a4e0): init from utils.Stopper
### Pkg/Timeutil
- [45ecf18](https://github.com/quay/clair/commit/45ecf1881521281f09e437c904e1f211dc36e319): init
### Prometheus
- [4f0f813](https://github.com/quay/clair/commit/4f0f8136c0459565ec0fcfb5c6035075f49d28b3): fix grafana's updater notes graph
- [cf3573c](https://github.com/quay/clair/commit/cf3573cf671ec0f14344d8ee072e3abdf030bbcc): correct notifier latency metric in grafana
- [3defe64](https://github.com/quay/clair/commit/3defe6448a9e8cf8cdcdb4294330a1077acf3918): add quantile to grafana
- [0c5cdab](https://github.com/quay/clair/commit/0c5cdab0b15f1d67dc755f9b068c50371d4390f9): update grafana
- [baed60e](https://github.com/quay/clair/commit/baed60e19ba5e58271cbe30aecb09404716e4a99): add initial Prometheus support
### Psql
- [9dc0026](https://github.com/quay/clair/commit/9dc002621abe5283e7f4fa645a6c8b8d823b6a95): add useful indexes
- [363cde2](https://github.com/quay/clair/commit/363cde29f4139953485a3ec04743025b35271c22): add debug message for duplicate layers
### Psql/Migrations
- [9338f28](https://github.com/quay/clair/commit/9338f28e82bf01f7571f0419e0344a8cd5e1ce6a): fix ordering
### README
- [4db72b8](https://github.com/quay/clair/commit/4db72b8c26a5754d61931c2fd5a6ee1829b9f016): fixed issues address
- [6c3b398](https://github.com/quay/clair/commit/6c3b398607f701ac8f016c804f2b2883c0ca1db9): fix IRC copypasta
- [f36aa12](https://github.com/quay/clair/commit/f36aa12024ad430843110ca2a23140664f6c621d): clean up after README refactor
- [3b2c4e5](https://github.com/quay/clair/commit/3b2c4e5e92aaa49d2e90a5c2ab39fb79cbed4117): improve readability
- [346c22f](https://github.com/quay/clair/commit/346c22fe28db34f87959e5f7a4931940fb926a08): s/Namespace/Feature Namespace
- [6c90635](https://github.com/quay/clair/commit/6c90635848da7aa3d5c7ed011773de93cf119775): update to reflect ext directory
- [67be72b](https://github.com/quay/clair/commit/67be72b97e581a0d54d2a1f20a9ac54404a04819): rm images from repo
- [a1bbd7d](https://github.com/quay/clair/commit/a1bbd7dbf0d71e72cf8b2284aff8ca2326162709): add git dependency
- [805f620](https://github.com/quay/clair/commit/805f620b4b4e84514ac139b49c0d88cd85a4625e): add alpine data sources
- [861cba0](https://github.com/quay/clair/commit/861cba0f49101d117a3d49aed34a9ed11f4f91a4): s/1.2.2/1.2.4
- [4bc6416](https://github.com/quay/clair/commit/4bc6416132dd5d3586d08a17d358adeeb760269e): include data licenses for data sources ([#219](https://github.com/quay/clair/issues/219))
 -  [#219](https://github.com/quay/clair/issues/219)- [c4281b3](https://github.com/quay/clair/commit/c4281b3a3c9c90beed7ea723a0a343ad80068e1e): add reference to Klar tool
- [4246c52](https://github.com/quay/clair/commit/4246c5244bbcffb9d278617a80bbe184bb8e935d): add master branch warning
- [4ab49ee](https://github.com/quay/clair/commit/4ab49ee0a0615f631f2f8a150c97c1bdc5527f67): Fix Kubernetes instructions
- [9ce0956](https://github.com/quay/clair/commit/9ce0956f1af348b4b0180e30e4b958b335faece4): add instructions for kubernetes
- [e72f0e6](https://github.com/quay/clair/commit/e72f0e69232529b63cb6be1bd7bc431c3bfe2eb8): Reduce logo size
- [9573acb](https://github.com/quay/clair/commit/9573acbc1bea515bd3187d9f7e6dc5f6fde13212): Add logo
- [f6ba17d](https://github.com/quay/clair/commit/f6ba17dfc7a4c5e516f970d795851b4a8cf0bbbc): Update Docker Compose instructions
- [20ecc84](https://github.com/quay/clair/commit/20ecc847d99305e984a0d39e5766bb869c1ba556): Add FeatureDetector and NamespaceDetector
- [440b5d5](https://github.com/quay/clair/commit/440b5d58cdef2ea7c3e3ba77fa3182a2ba25e4ed): fix godoc badge copypasta
- [ec8cf9f](https://github.com/quay/clair/commit/ec8cf9fb26efc4a59359e78048ac01a49ac839f9): add documentation with links
- [fe1e066](https://github.com/quay/clair/commit/fe1e06669f80d66794341557edd7befd2dc2618b): nitpick
- [6b8e198](https://github.com/quay/clair/commit/6b8e198ef917f25794e688f5e5601f6d396e6d7e): fix link
- [80977f2](https://github.com/quay/clair/commit/80977f233ed5fbc10670638649080e28657c5481): add go report card
- [c61eeba](https://github.com/quay/clair/commit/c61eebafdfad2f241e9aca1f1815b17db860f329): move diagram to architecture section
- [6e196e4](https://github.com/quay/clair/commit/6e196e416da89eb8947cddc295157d7384c7073e): add diagram & custom data sources
- [ef7ccd3](https://github.com/quay/clair/commit/ef7ccd3773c4e87c738357275a172a16e08c7c6c): minor grammar/spelling tweaks
- [a10260c](https://github.com/quay/clair/commit/a10260c80d6ea2ba5ab65d2164b2e625d1eb2a99): add container badge
### ROADMAP
- [e9eb761](https://github.com/quay/clair/commit/e9eb761db6d4093a2cbb907c14a0a99ae4c5982c): refresh with current priorities
### Readme
- [a8c58d4](https://github.com/quay/clair/commit/a8c58d4e3d1e2190c54bcfcbe6a637ce9e946827): add various talks & slides
- [93f7f10](https://github.com/quay/clair/commit/93f7f10bf71ddfe353d4751d5f9c337bdb52f420): replace latest by v1.2.2 and add reference to container repositories
- [49fa75a](https://github.com/quay/clair/commit/49fa75a64abe50e1be134fd542b6973fa2ac4624): split "Related Links" into projects/slides ([#177](https://github.com/quay/clair/issues/177))
 -  [#177](https://github.com/quay/clair/issues/177) - Fixes [#173](https://github.com/quay/clair/issues/173)- [b383767](https://github.com/quay/clair/commit/b3837673feefba04f7fc08d9fdeda7f0edb08d68): add dependencies to getting started
- [0979b01](https://github.com/quay/clair/commit/0979b01a44a1555273ebb6db4b42cbfab93253d5): add terminology and generic customization
- [d47616a](https://github.com/quay/clair/commit/d47616a33969b7d880021ca24eca265128cc6ed1): make API description consistence
- [af0ddce](https://github.com/quay/clair/commit/af0ddceaa2b8b914d8d7a49a538dc54281172a65): s/notification/notifications
- [2140995](https://github.com/quay/clair/commit/2140995a54040496961cc55e31871279a559bc17): clarify "marked as read" notifications
- [f48f94c](https://github.com/quay/clair/commit/f48f94cbd0f4e9c2205705bddc05f2ad3b3c74eb): continue to nitpick
- [cadc182](https://github.com/quay/clair/commit/cadc182cc41ee66cb08a7d8be8fbca08100c3fad): add travis-ci badge
### Redhatrelease
- [ce8d31b](https://github.com/quay/clair/commit/ce8d31bbb323471bf2a69427e4a645b3ce8a25c1): override match for RHEL hosts
### Refactor
- [4a99037](https://github.com/quay/clair/commit/4a990372fff35f606184e276976f0279e4ea5a56): move updaters and notifier into ext
### Style
- [bd68578](https://github.com/quay/clair/commit/bd68578b8bdd4488e197ccdf6d9322380c6ae7d0): Fix typo in headline
### Tarutil
- [a3a3707](https://github.com/quay/clair/commit/a3a37072b54840aaebde1cd0bba62b8939dafbdc): convert all filename specs to regexps
- [afd7fe2](https://github.com/quay/clair/commit/afd7fe2554d65040b27291d658af21af8f8ae521): allow file names to be specified by regexp
 - fixes [#456](https://github.com/quay/clair/issues/456)### Travis
- [52ecf35](https://github.com/quay/clair/commit/52ecf35ca67558c1bedefb2259e9af9ad9649f9d): fail if not gofmt -s
- [7492aa3](https://github.com/quay/clair/commit/7492aa31baf5b834088ecb8e8bd6ffd7817e5dd7): fail unformatted protos
- [4fab327](https://github.com/quay/clair/commit/4fab327397a1d9484809768fe357428599b510d6): add matrix for postgres
- [2d0be7c](https://github.com/quay/clair/commit/2d0be7ccf46c60717fc19049edfd6ded4bb6ee0e): update to use Go 1.7, glide
- [bed3662](https://github.com/quay/clair/commit/bed3662e64881f2eb8828937427d9e0ab1893654): allow golang 'tip' failures ([#202](https://github.com/quay/clair/issues/202))
 -  [#202](https://github.com/quay/clair/issues/202)- [0423f97](https://github.com/quay/clair/commit/0423f976b72a73f9708d60e9ef06a0e4acb456c3): test against Go 1.6
- [02d3884](https://github.com/quay/clair/commit/02d38843cb5b4f0708ab0fd9790b60c50d17c19d): disable install step
- [1b55d38](https://github.com/quay/clair/commit/1b55d387f6373ecea4ffeec92c0f995024f8d54c): add missing rpm dependency
- [5873ab8](https://github.com/quay/clair/commit/5873ab892cb83b30478eecad2b41efc769b7a41d): initial travis.yml
### Travis
- [870e812](https://github.com/quay/clair/commit/870e8123769a3dd717bfdcd21473a8e691806653): Drop support for postgres 9.4 postgres 9.4 doesn't support ON CONFLICT, which is required in our implementation.
### Update Documentation
- [1105102](https://github.com/quay/clair/commit/1105102b8449fcf20b8db1b1722eeeeece2f33fa): talk about SUSE support
### Update The Ingress To Use ApiVersion
- [435d053](https://github.com/quay/clair/commit/435d05394a9e7895d8daf2804bbe3668e1666981): networking.k8s.io/v1beta1
### Updater
- [7084a22](https://github.com/quay/clair/commit/7084a226ae9c5a3aed1248ad3d653100d610146c): extract deduplicate function
- [e16d17d](https://github.com/quay/clair/commit/e16d17dda9d29e8fdc33ef9da6a4a8be0e6b648f): remove original RunUpdate()
- [0d41968](https://github.com/quay/clair/commit/0d41968acdeeb2325bf9573a65fd1d05345ba255): reimplement fetch() with errgroup
- [6c5be7e](https://github.com/quay/clair/commit/6c5be7e1c6856fbae55e77c0a3411e7fe4d61f82): refactor to use errgroup
- [2236b0a](https://github.com/quay/clair/commit/2236b0a5c9a094bde2b7979417b9538cb944e726): Add vulnsrc affected feature type
- [0d18a62](https://github.com/quay/clair/commit/0d18a629cab15d57fb7b00777f1537039b69401b): sleep before continuing the lock loop
 - Fixes [#415](https://github.com/quay/clair/issues/415)- [edfadc2](https://github.com/quay/clair/commit/edfadc2f870776a14feaa46da35bceab5b0f9c74): Log fetch completion
- [b792eb6](https://github.com/quay/clair/commit/b792eb61f69c8e9c100675970ac4d928fd2b5e98): copy whole namespace when deduping vulns
- [9639846](https://github.com/quay/clair/commit/96398465dea9f86b569cacc7d3677db2f09a763b): Set vulns' Severity from NVD metadata fetcher if unknown
- [1c3daa2](https://github.com/quay/clair/commit/1c3daa23b9e6fb76a9b0b283d3b2a5e1037b50b6): minimize vulns' lock duration in the NVD metadata fetcher
- [be97db5](https://github.com/quay/clair/commit/be97db52611b69aab97db3b90e2b371349e137b2): enable fetching of RHEL 5 vulnerabilities ([#217](https://github.com/quay/clair/issues/217))
 -  [#217](https://github.com/quay/clair/issues/217) - Fixes [#215](https://github.com/quay/clair/issues/215)- [34f62ef](https://github.com/quay/clair/commit/34f62ef1f1a61895ccbb997eabea6d904d0d4cc8): delete Ubuntu's repository upon bzr errors
 - Fixes [#169](https://github.com/quay/clair/issues/169)- [45ed80d](https://github.com/quay/clair/commit/45ed80df1b455b094ad2d6911b47010e228f3760): remove useless error
- [2126259](https://github.com/quay/clair/commit/2126259c9974d13eef118b49fbd972b6fbf05b3c): use a better link for Ubuntu vulnerabilities and rename some constants
- [431c0cc](https://github.com/quay/clair/commit/431c0ccb03f152ba60d1c465c682c39aa96ab8df): add a clean function to fetchers
- [3ecb8b6](https://github.com/quay/clair/commit/3ecb8b69cb6823f2672fd5f5e59c9bdb30537894): ignore "ubuntu-core" in the Ubuntu fetcher
- [8e85234](https://github.com/quay/clair/commit/8e852348a12593173e9d06726399a8c8d899b363): ensure that ubuntu's notes are unique
- [99de759](https://github.com/quay/clair/commit/99de759224089d70b4934099a38e99cd7641a0e3): namespace and split Ubuntu/RHEL vulnerabilities
- [847c649](https://github.com/quay/clair/commit/847c6492886ba85542759265399c0fd1e199dd63): update RHEL fetcher and add not-affected capability
- [ea59b0e](https://github.com/quay/clair/commit/ea59b0e45f36c0458876b9481463df748da43eee): update Ubuntu fetcher and add not-affected capability
- [7e72eb1](https://github.com/quay/clair/commit/7e72eb10b66bfddb865e184e0dc56a839c411e70): ignore Debian's "temp" vulnerabilities
- [77387af](https://github.com/quay/clair/commit/77387af2ac9a8c9e900b9e362687d0c3a46121b8): port updater and its fetchers
- [452f701](https://github.com/quay/clair/commit/452f7018ecf55d5f3770d15f0e740ae332ada30c): move each fetcher to its own package
- [e91365f](https://github.com/quay/clair/commit/e91365f4b3ca6e6b7c30cea7d6700679a313b734): fix typos
- [712aa11](https://github.com/quay/clair/commit/712aa11b8b566be8a1c471481667c6a6f633f08f): Add support for Ubuntu Vivid Core and ignore Vivid PhoneOverlay
- [c055c33](https://github.com/quay/clair/commit/c055c33cf8cef8279c5f3c7d0ea5e0fd7e9a47b3): Fix Ubuntu's partial update bug.
- [a7b683d](https://github.com/quay/clair/commit/a7b683d4ba8420a1ad18c5392517774f82ce14d6): Refactor and merge fetcher responses
 - Fixes [#17](https://github.com/quay/clair/issues/17) -  [#19](https://github.com/quay/clair/issues/19)- [2452a8f](https://github.com/quay/clair/commit/2452a8fc488f7ef6dd245bf0299e931d7453e0d5): Always use `bzr revno` to get Ubuntu db's revision number.
 - Fixes [#7](https://github.com/quay/clair/issues/7)### Updater
- [a14b372](https://github.com/quay/clair/commit/a14b372838a72d24110b57c6443d784d6fbe4451): fix stuck updater process
### Updater,Pkg/Timeutil
- [f64bd11](https://github.com/quay/clair/commit/f64bd117b2fa946c26a2e3368925f6dae8e4a2d3): minor cleanups
### Updater/Database
- [7c11e4e](https://github.com/quay/clair/commit/7c11e4eb5da948c77a53820398d0ced42dca5601): do not create notifications during the initial update
### Updater/Fetchers
- [0cb8fc9](https://github.com/quay/clair/commit/0cb8fc9455905c658732fbc36ee9efe41fb78de5): add alpine secdb fetcher
### Updater/Worker
- [85fa3f9](https://github.com/quay/clair/commit/85fa3f9a38ee625c005c375d0412cf8b7c131ff8): adapt several tests
### Upgrade To Golang
- [db5dbbe](https://github.com/quay/clair/commit/db5dbbe4e983a4ac827f5b6597aac780c03124b3): 1.10-alpine
### Utils
- [3e4dc38](https://github.com/quay/clair/commit/3e4dc3834f539d67829d83cf42c4c978611ab83e): remove string.go
- [c2f4a44](https://github.com/quay/clair/commit/c2f4a4406812f85658615305f52329ec688975e5): rm exec.go
- [e7f72ef](https://github.com/quay/clair/commit/e7f72ef5adca478985545dfafd9d0011e098367c): rm prometheus.go
- [1faf27b](https://github.com/quay/clair/commit/1faf27ba185bbad2e12558accb65b6460d5ee682): Fix OVAL's log statements
### Utils/Http
- [02e2c58](https://github.com/quay/clair/commit/02e2c5823670d9587a2143a231adfa3cd38a87bb): remove unused pkg
### V1
- [4fd4049](https://github.com/quay/clair/commit/4fd4049fee70539bbf2acee7e451cb35ae476c3f): update documented error codes
- [452c32d](https://github.com/quay/clair/commit/452c32d7d7ff412a4a9c069f07eef220e16686bd): pagination now deterministic
- [dc431c2](https://github.com/quay/clair/commit/dc431c22f34660746e7efa19d86cd846b1272b70): add readme
- [771e35d](https://github.com/quay/clair/commit/771e35def021863d5f6b94536f87a5812718e01f): return object on PUT/POST
- [c06df1a](https://github.com/quay/clair/commit/c06df1affdf60e35e2be7811be2469e4ee3bf827): 200 on PUT
### V3
- [88f5069](https://github.com/quay/clair/commit/88f506918b9cb32ab77e41e0cbbe2f9db6e6b358): Analyze layer content in parallel
- [dd23976](https://github.com/quay/clair/commit/dd239762f63702c1800895ee9b86bdda316830ef): Move services to top of the file
- [9f5d1ea](https://github.com/quay/clair/commit/9f5d1ea4e16793ebd9390673aed34855671b5c24): associate feature and namespace with detector
### Various
- [500fc4e](https://github.com/quay/clair/commit/500fc4e407961419dac87072123a21adc2c6f15b): gofmt -s
- [8fd0aa1](https://github.com/quay/clair/commit/8fd0aa162bb847c1a81e84920b2e4a04daf41d62): spelling corrections
### Vendor
- [4106322](https://github.com/quay/clair/commit/41063221075cea67636f77f58a9d3e112771b835): Update gopkg.in/yaml.v2 package
- [34d0e51](https://github.com/quay/clair/commit/34d0e516e0792ca2d06299a1262e5676d4145f80): Add golang-set dependency
- [55ecf1e](https://github.com/quay/clair/commit/55ecf1e58aa75346ca6c4d702eb31e02ff32ee0e): regenerate after removing graceful
- [1533dd1](https://github.com/quay/clair/commit/1533dd1d51d4f89febd857897addb6dfb6c161e4): updated vendor dir for grpc v2 api
- [35df9d5](https://github.com/quay/clair/commit/35df9d5846d5b69e832d987a87e9ba4d838d4178): regenerate vendor directory with glide
- [50d07cc](https://github.com/quay/clair/commit/50d07ccf597e95dad6d0ceff386aa14e3d062d77): rm everything to prep for regeneration
### Versionfmt
- [8d29bf8](https://github.com/quay/clair/commit/8d29bf860d363a6ef061a4a4f3c1276e365966b4): convert to using constant over literal
- [6864a8e](https://github.com/quay/clair/commit/6864a8efead0337c7af700c60f1ed85b8a15ff9f): init rpm versionfmt
### Versionfmt/Dpkg
- [1e9f14a](https://github.com/quay/clair/commit/1e9f14ae33963d5dea1ec5217ba9069934e2e655): remove leading digit requirement
### Versionfmt/Rpm
- [db8a133](https://github.com/quay/clair/commit/db8a133d2130e8a6b9f598c4bd859b06a5a0a8af): handle a tilde correctly
### Vulnmdsrc
- [ce6b008](https://github.com/quay/clair/commit/ce6b00887b1db3a402b1a02bdebb5bcc23d4add0): update NVD URLs
 - Fixes [#575](https://github.com/quay/clair/issues/575)### Vulnsrc
- [72674ca](https://github.com/quay/clair/commit/72674ca871dd2b0a9afdbd9c6a6b50f49a50b20b): Refactor vulnerability sources to use utility functions
### Vulnsrc Rhel
- [bd7102d](https://github.com/quay/clair/commit/bd7102d96304b02ff09077edc16f5f60bd784c8b): handle "none" CVE impact
### Vulnsrc/Alpine
- [c031f8e](https://github.com/quay/clair/commit/c031f8ea0c793ba0462f2b8a204c15ab3a65f1a5): s/pull/clone
- [4c2be52](https://github.com/quay/clair/commit/4c2be5285e1419844377c11484bd684b45948958): avoid shadowing vars
- [c8622d5](https://github.com/quay/clair/commit/c8622d5f3472698e872b7b6a6ff817da42bbcf07): unify schema and parse v3.5
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
 - Fixes [#495](https://github.com/quay/clair/issues/495)### Webhook
- [8c282fd](https://github.com/quay/clair/commit/8c282fdb5a73e2b6579bbafb367c68d45766f760): add JSON envelope
### Worker
- [23ccd9b](https://github.com/quay/clair/commit/23ccd9b53ba0a8bcf800fecdbd72d5cbefd2ea60): Fix tests for feature_type
- [f0e21df](https://github.com/quay/clair/commit/f0e21df7830e3f8d00498936d0d292ae6ff6765b): fixed duplicated ns and ns not inherited bug
- [ce6eba9](https://github.com/quay/clair/commit/ce6eba9fcb8f037a644f1790d690ad846559d274): Rewrite unknown namespace warning
- [8bedd0a](https://github.com/quay/clair/commit/8bedd0a3670dfe2bc60d3b750c981441f91d32c8): ns detectors now support VersionFormat
- [de1f09e](https://github.com/quay/clair/commit/de1f09e8b375ae79a16349dee74d2dd664a606bd): clarify maxFileSize purpose
 - Fixes [#237](https://github.com/quay/clair/issues/237)- [2cb23ce](https://github.com/quay/clair/commit/2cb23ced02b3cdbbb2de62d042562fe2fc68dc2e): bump engine version
- [8551a0a](https://github.com/quay/clair/commit/8551a0a3b2a0b93867395dce3efc6156ed642aad): Mock datastore in worker's tests
- [bae5a5e](https://github.com/quay/clair/commit/bae5a5e3ad15719f4094d2f766937952d5576fad): remove duplicated tests
- [c2605e0](https://github.com/quay/clair/commit/c2605e0bf2db061ad56b70823a33724e2ec606d9): verify download status code
- [41736e4](https://github.com/quay/clair/commit/41736e4600ae0314c039ec7b931491f132af9999): DetectData should return an error if the supported detector failed
- [98ed041](https://github.com/quay/clair/commit/98ed041956b6710b56a645949692c0c950b0e82d): remove double error
- [9b51f7f](https://github.com/quay/clair/commit/9b51f7f4fbf4d9e700d7accc8802265de23a99c6): raise worker version number
- [2f57f0d](https://github.com/quay/clair/commit/2f57f0d4b1a65e4b426f9da4d27fd405d399e9e5): change worker errors to bad request errors
- [b3ddfbc](https://github.com/quay/clair/commit/b3ddfbc3538bae97e7b6875e3bdfc97e31383f33): remove namespace whitelist
- [90fe137](https://github.com/quay/clair/commit/90fe137de82f10df644a1671ee12fc91afbeb1ab): move each data detector to their own packages and remove image format whitelist
- [34842fd](https://github.com/quay/clair/commit/34842fd8f77a200a77f546dce8728f63fb378675): fix dpkg detector and adapt tests
- [343ce39](https://github.com/quay/clair/commit/343ce39865dc2994c0bd8c4d9f75c5be476fe1b0): detect the status code when downloading a layer and expect 2XX.
- [ac0e68e](https://github.com/quay/clair/commit/ac0e68efe7fee01f01bfdc7b13de513e29e69f91): Add a missing CleanURL
### Worker/Database
- [a38fbf6](https://github.com/quay/clair/commit/a38fbf6cfe3345cd7b684a1d38d8021f9e7c8e2a): Move upgrade detection logic out of database to worker
### Workflows
- [e1902d4](https://github.com/quay/clair/commit/e1902d4d7c1f7d7fdccc6b339736966d2ece0cf6): proper tag name
- [b2d781c](https://github.com/quay/clair/commit/b2d781c2ed50262f4882e34b2585bf99d80fb15b): bad tar flag
### Reverts
- Merge pull request [#199](https://github.com/quay/clair/issues/199) from openSUSE/feature/opensuse
- v1: pagination now deterministic

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
- Merge pull request [#395](https://github.com/quay/clair/issues/395) from knqyf263/handle_tilde
- Merge pull request [#392](https://github.com/quay/clair/issues/392) from jzelinskie/https-sec-db
- Merge pull request [#390](https://github.com/quay/clair/issues/390) from KeyboardNerd/fernet
- Merge pull request [#389](https://github.com/quay/clair/issues/389) from jzelinskie/revendor
- Merge pull request [#387](https://github.com/quay/clair/issues/387) from jzelinskie/rm-analyze-local-images
- Merge pull request [#385](https://github.com/quay/clair/issues/385) from KeyboardNerd/logrus
- Merge pull request [#381](https://github.com/quay/clair/issues/381) from KeyboardNerd/bill-of-materials
- Merge pull request [#373](https://github.com/quay/clair/issues/373) from josuesdiaz/fix_analyze_local
- Merge pull request [#378](https://github.com/quay/clair/issues/378) from jzelinskie/oracle-update-fix
- Merge pull request [#374](https://github.com/quay/clair/issues/374) from tianon/new-ubuntu-releases
- Merge pull request [#371](https://github.com/quay/clair/issues/371) from caipre/add-logging
- Merge pull request [#370](https://github.com/quay/clair/issues/370) from jzelinskie/featurens
- Merge pull request [#369](https://github.com/quay/clair/issues/369) from jzelinskie/fix-ali
- Merge pull request [#367](https://github.com/quay/clair/issues/367) from jzelinskie/analyze-layers-v2
- Merge pull request [#366](https://github.com/quay/clair/issues/366) from jzelinskie/fixoracle
- Merge pull request [#361](https://github.com/quay/clair/issues/361) from jzelinskie/ROADMAP.md
- Merge pull request [#363](https://github.com/quay/clair/issues/363) from davidxia/patch-1
- Merge pull request [#362](https://github.com/quay/clair/issues/362) from jzelinskie/malformedpkg
- Merge pull request [#360](https://github.com/quay/clair/issues/360) from jzelinskie/cleanup
- Merge pull request [#359](https://github.com/quay/clair/issues/359) from matslina/patch-1
- Merge pull request [#357](https://github.com/quay/clair/issues/357) from jzelinskie/readme-reboot
- Merge pull request [#352](https://github.com/quay/clair/issues/352) from kevinburke/fix-404
- Merge pull request [#354](https://github.com/quay/clair/issues/354) from kevinburke/change-readme-text
- Merge pull request [#347](https://github.com/quay/clair/issues/347) from jzelinskie/composeup
- Merge pull request [#348](https://github.com/quay/clair/issues/348) from supereagle/update-image-spec-url
- Merge pull request [#341](https://github.com/quay/clair/issues/341) from pizzarabe/Readme_Alpine35
- Merge pull request [#340](https://github.com/quay/clair/issues/340) from coreos/philips-patch-1
- Merge pull request [#338](https://github.com/quay/clair/issues/338) from pgburt/paulb-prod-users-integrations
- Merge pull request [#335](https://github.com/quay/clair/issues/335) from jzelinskie/fixns
- Merge pull request [#334](https://github.com/quay/clair/issues/334) from supereagle/update-dockerfile
- Merge pull request [#331](https://github.com/quay/clair/issues/331) from supereagle/insecure-tls
- Merge pull request [#328](https://github.com/quay/clair/issues/328) from jgsqware/master
- Merge pull request [#327](https://github.com/quay/clair/issues/327) from jzelinskie/bad-ns-copy
- Merge pull request [#326](https://github.com/quay/clair/issues/326) from Quentin-M/alpine_dfile
- Merge pull request [#324](https://github.com/quay/clair/issues/324) from Quentin-M/log_ns
- Merge pull request [#325](https://github.com/quay/clair/issues/325) from Quentin-M/alpine_dfile
- Merge pull request [#316](https://github.com/quay/clair/issues/316) from jzelinskie/fix-alpine
- Merge pull request [#305](https://github.com/quay/clair/issues/305) from jzelinskie/ext
- Merge pull request [#309](https://github.com/quay/clair/issues/309) from jzelinskie/fixmigration6
- Merge pull request [#308](https://github.com/quay/clair/issues/308) from jzelinskie/fixpagination
- Merge pull request [#307](https://github.com/quay/clair/issues/307) from jzelinskie/layeridorder
- Merge pull request [#302](https://github.com/quay/clair/issues/302) from jzelinskie/rmimage
- Merge pull request [#301](https://github.com/quay/clair/issues/301) from jzelinskie/readme-git
- Merge pull request [#298](https://github.com/quay/clair/issues/298) from jzelinskie/versions
- Merge pull request [#300](https://github.com/quay/clair/issues/300) from miketheman/patch-1
- Merge pull request [#299](https://github.com/quay/clair/issues/299) from alexei-led/master
- Merge pull request [#295](https://github.com/quay/clair/issues/295) from jzelinskie/fixmigrationorder
- Merge pull request [#290](https://github.com/quay/clair/issues/290) from Djelibeybi/oraclelinux-support
- Merge pull request [#288](https://github.com/quay/clair/issues/288) from jzelinskie/200mb
- Merge pull request [#289](https://github.com/quay/clair/issues/289) from jzelinskie/revert-suse
- Merge pull request [#287](https://github.com/quay/clair/issues/287) from jzelinskie/enginebump
- Merge pull request [#272](https://github.com/quay/clair/issues/272) from jzelinskie/alpine
- Merge pull request [#282](https://github.com/quay/clair/issues/282) from jzelinskie/layer-sort-id
- Merge pull request [#280](https://github.com/quay/clair/issues/280) from coreos/add_idx_deleted_at
- Merge pull request [#281](https://github.com/quay/clair/issues/281) from coreos/dis_hashjoins_introducing
- Merge pull request [#277](https://github.com/quay/clair/issues/277) from jzelinskie/travispg
- Merge pull request [#279](https://github.com/quay/clair/issues/279) from coreos/searchintro_optimize
- Merge pull request [#278](https://github.com/quay/clair/issues/278) from jzelinskie/layerdiffindex
- Merge pull request [#276](https://github.com/quay/clair/issues/276) from jzelinskie/index
- Merge pull request [#274](https://github.com/quay/clair/issues/274) from JensPiegsa/patch-1
- Merge pull request [#271](https://github.com/quay/clair/issues/271) from Quentin-M/nvd_severity
- Merge pull request [#270](https://github.com/quay/clair/issues/270) from Quentin-M/imp_docs
- Merge pull request [#263](https://github.com/quay/clair/issues/263) from Quentin-M/rhel_unique_fixedin
- Merge pull request [#261](https://github.com/quay/clair/issues/261) from Quentin-M/replace_goose
- Merge pull request [#262](https://github.com/quay/clair/issues/262) from jzelinskie/travis
- Merge pull request [#257](https://github.com/quay/clair/issues/257) from mattmoor/yakkety
- Merge pull request [#199](https://github.com/quay/clair/issues/199) from openSUSE/feature/opensuse
- Merge pull request [#236](https://github.com/quay/clair/issues/236) from robszumski/doc-link
- Merge pull request [#235](https://github.com/quay/clair/issues/235) from jzelinskie/doc-move
- Merge pull request [#229](https://github.com/quay/clair/issues/229) from vbatts/redhatrelease_detector
- Merge pull request [#216](https://github.com/quay/clair/issues/216) from optiopay/doc-klar-ref
- Merge pull request [#205](https://github.com/quay/clair/issues/205) from Quentin-M/readme_v122
- Merge pull request [#206](https://github.com/quay/clair/issues/206) from Quentin-M/godeps_implsubmod
- Merge pull request [#186](https://github.com/quay/clair/issues/186) from Quentin-M/delete_ubuntu_repository
- Merge pull request [#196](https://github.com/quay/clair/issues/196) from jgsqware/integrate-glide
- Merge pull request [#188](https://github.com/quay/clair/issues/188) from databus23/patch-1
- Merge pull request [#165](https://github.com/quay/clair/issues/165) from Quentin-M/db_registration
- Merge pull request [#166](https://github.com/quay/clair/issues/166) from jzelinskie/authlayer
- Merge pull request [#158](https://github.com/quay/clair/issues/158) from Quentin-M/contrib_cleanup_signals
- Merge pull request [#143](https://github.com/quay/clair/issues/143) from jzelinskie/travis
- Merge pull request [#142](https://github.com/quay/clair/issues/142) from jzelinskie/healthfix
- Merge pull request [#139](https://github.com/quay/clair/issues/139) from coreos/webhook_proxy
- Merge pull request [#137](https://github.com/quay/clair/issues/137) from coreos/fix_k8s
- Merge pull request [#126](https://github.com/quay/clair/issues/126) from harsha-y/master
- Merge pull request [#118](https://github.com/quay/clair/issues/118) from coreos/cleanup_contrib
- Merge pull request [#123](https://github.com/quay/clair/issues/123) from coreos/contrib_fix_deadlink
- Merge pull request [#116](https://github.com/quay/clair/issues/116) from BWITS/master
- Merge pull request [#110](https://github.com/quay/clair/issues/110) from jzelinskie/config-fixes
- Merge pull request [#111](https://github.com/quay/clair/issues/111) from jzelinskie/dockerfile-update
- Merge pull request [#108](https://github.com/quay/clair/issues/108) from philips/add-k8s-contrib
- Merge pull request [#107](https://github.com/quay/clair/issues/107) from Quentin-M/reduce_logo
- Merge pull request [#106](https://github.com/quay/clair/issues/106) from Quentin-M/logo
- Merge pull request [#105](https://github.com/quay/clair/issues/105) from coreos/crtrb_forcecolor
- Merge pull request [#104](https://github.com/quay/clair/issues/104) from coreos/ctrb_minseverity
- Merge pull request [#103](https://github.com/quay/clair/issues/103) from jzelinskie/fix-config
- Merge pull request [#101](https://github.com/quay/clair/issues/101) from Quentin-M/ctrb_minseverity
- Merge pull request [#100](https://github.com/quay/clair/issues/100) from jzelinskie/namespaces
- Merge pull request [#96](https://github.com/quay/clair/issues/96) from jzelinskie/rootyamlkey
- Merge pull request [#85](https://github.com/quay/clair/issues/85) from keloyang/allowHost
- Merge pull request [#94](https://github.com/quay/clair/issues/94) from unageanu/support-docker-compose
- Merge pull request [#82](https://github.com/quay/clair/issues/82) from liangchenye/getvulns
- Merge pull request [#91](https://github.com/quay/clair/issues/91) from Quentin-M/fix_pprof
- Merge pull request [#90](https://github.com/quay/clair/issues/90) from jzelinskie/README-deps
- Merge pull request [#89](https://github.com/quay/clair/issues/89) from Quentin-M/fv_find_before_lock
- Merge pull request [#83](https://github.com/quay/clair/issues/83) from coreos/readme-feature-namespace
- Merge pull request [#81](https://github.com/quay/clair/issues/81) from coolljt0725/fix_readme
- Merge pull request [#79](https://github.com/quay/clair/issues/79) from liangchenye/v1doc
- Merge pull request [#77](https://github.com/quay/clair/issues/77) from coreos/simplify
- Merge pull request [#76](https://github.com/quay/clair/issues/76) from coreos/sp
- Merge pull request [#71](https://github.com/quay/clair/issues/71) from Quentin-M/sql
- Merge pull request [#75](https://github.com/quay/clair/issues/75) from sjourdan/fix_vuln_typo
- Merge pull request [#73](https://github.com/quay/clair/issues/73) from maxking/doc
- Merge pull request [#74](https://github.com/quay/clair/issues/74) from mnuessler/causedByPackage
- Merge pull request [#70](https://github.com/quay/clair/issues/70) from liangchenye/read-manifest
- Merge pull request [#67](https://github.com/quay/clair/issues/67) from Quentin-M/master
- Merge pull request [#65](https://github.com/quay/clair/issues/65) from jzelinskie/fixdockerfile
- Merge pull request [#49](https://github.com/quay/clair/issues/49) from liangchenye/master
- Merge pull request [#59](https://github.com/quay/clair/issues/59) from davidxia/patch1
- Merge pull request [#52](https://github.com/quay/clair/issues/52) from Quentin-M/custom_notifiers
- Merge pull request [#53](https://github.com/quay/clair/issues/53) from coreos/ubdater
- Merge pull request [#46](https://github.com/quay/clair/issues/46) from coreos/fix_sql_tovalue
- Merge pull request [#47](https://github.com/quay/clair/issues/47) from coreos/sn
- Merge pull request [#51](https://github.com/quay/clair/issues/51) from coolljt0725/update_analyze_local_image_doc
- Merge pull request [#50](https://github.com/quay/clair/issues/50) from coolljt0725/fix_stop
- Merge pull request [#44](https://github.com/quay/clair/issues/44) from Quentin-M/configfile
- Merge pull request [#42](https://github.com/quay/clair/issues/42) from Quentin-M/triple
- Merge pull request [#35](https://github.com/quay/clair/issues/35) from mrqwer88/check_openvz_mirror_with_clair
- Merge pull request [#29](https://github.com/quay/clair/issues/29) from Quentin-M/notifier_tls
- Merge pull request [#22](https://github.com/quay/clair/issues/22) from Quentin-M/predcst
- Merge pull request [#41](https://github.com/quay/clair/issues/41) from coreos/travisfix
- Merge pull request [#33](https://github.com/quay/clair/issues/33) from Quentin-M/insertvulns
- Merge pull request [#36](https://github.com/quay/clair/issues/36) from coreos/gc
- Merge pull request [#39](https://github.com/quay/clair/issues/39) from coreos/travis
- Merge pull request [#37](https://github.com/quay/clair/issues/37) from Quentin-M/updater_refactor
- Merge pull request [#38](https://github.com/quay/clair/issues/38) from Quentin-M/causedby
- Merge pull request [#26](https://github.com/quay/clair/issues/26) from stapelberg/patch-1
- Merge pull request [#25](https://github.com/quay/clair/issues/25) from fatalbanana/patch-1
- Merge pull request [#21](https://github.com/quay/clair/issues/21) from coreos/updatefix
- Merge pull request [#24](https://github.com/quay/clair/issues/24) from coreos/jonboulle-patch-1
- Merge pull request [#18](https://github.com/quay/clair/issues/18) from Quentin-M/local-analysis
- Merge pull request [#11](https://github.com/quay/clair/issues/11) from Quentin-M/bzr_parsing
- Merge pull request [#6](https://github.com/quay/clair/issues/6) from Quentin-M/reduce_tx
- Merge pull request [#4](https://github.com/quay/clair/issues/4) from Quentin-M/reduce_tx


[Unreleased]: https://github.com/quay/clair/compare/v4.1.0...HEAD
[v4.1.0]: https://github.com/quay/clair/compare/v4.1.0-alpha.3...v4.1.0
[v4.1.0-alpha.3]: https://github.com/quay/clair/compare/v4.1.0-alpha.2...v4.1.0-alpha.3
[v4.1.0-alpha.2]: https://github.com/quay/clair/compare/v4.1.0-alpha.1...v4.1.0-alpha.2
[v4.1.0-alpha.1]: https://github.com/quay/clair/compare/v4.0.5...v4.1.0-alpha.1
[v4.0.5]: https://github.com/quay/clair/compare/v4.0.4...v4.0.5
[v4.0.4]: https://github.com/quay/clair/compare/v4.0.3...v4.0.4
[v4.0.3]: https://github.com/quay/clair/compare/v4.0.2...v4.0.3
[v4.0.2]: https://github.com/quay/clair/compare/v4.0.1...v4.0.2
[v4.0.1]: https://github.com/quay/clair/compare/v4.0.0...v4.0.1
[v4.0.0]: https://github.com/quay/clair/compare/v4.0.0-rc.24...v4.0.0
[v4.0.0-rc.24]: https://github.com/quay/clair/compare/v4.0.0-rc.23...v4.0.0-rc.24
[v4.0.0-rc.23]: https://github.com/quay/clair/compare/v4.0.0-rc.22...v4.0.0-rc.23
[v4.0.0-rc.22]: https://github.com/quay/clair/compare/v4.0.0-rc.21...v4.0.0-rc.22
[v4.0.0-rc.21]: https://github.com/quay/clair/compare/v4.0.0-rc.20...v4.0.0-rc.21
[v4.0.0-rc.20]: https://github.com/quay/clair/compare/v4.0.0-rc.19...v4.0.0-rc.20
[v4.0.0-rc.19]: https://github.com/quay/clair/compare/v4.0.0-rc.18...v4.0.0-rc.19
[v4.0.0-rc.18]: https://github.com/quay/clair/compare/v4.0.0-rc.17...v4.0.0-rc.18
[v4.0.0-rc.17]: https://github.com/quay/clair/compare/v4.0.0-rc.16...v4.0.0-rc.17
[v4.0.0-rc.16]: https://github.com/quay/clair/compare/v4.0.0-rc.15...v4.0.0-rc.16
[v4.0.0-rc.15]: https://github.com/quay/clair/compare/v4.0.0-rc.14...v4.0.0-rc.15
[v4.0.0-rc.14]: https://github.com/quay/clair/compare/v4.0.0-rc.13...v4.0.0-rc.14
[v4.0.0-rc.13]: https://github.com/quay/clair/compare/v4.0.0-rc.12...v4.0.0-rc.13
[v4.0.0-rc.12]: https://github.com/quay/clair/compare/v4.0.0-rc.11...v4.0.0-rc.12
[v4.0.0-rc.11]: https://github.com/quay/clair/compare/v4.0.0-rc.10...v4.0.0-rc.11
[v4.0.0-rc.10]: https://github.com/quay/clair/compare/v4.0.0-rc.9...v4.0.0-rc.10
[v4.0.0-rc.9]: https://github.com/quay/clair/compare/v4.0.0-rc.8...v4.0.0-rc.9
[v4.0.0-rc.8]: https://github.com/quay/clair/compare/v4.0.0-rc.7...v4.0.0-rc.8
[v4.0.0-rc.7]: https://github.com/quay/clair/compare/v4.0.0-rc.6...v4.0.0-rc.7
[v4.0.0-rc.6]: https://github.com/quay/clair/compare/v4.0.0-rc.5...v4.0.0-rc.6
[v4.0.0-rc.5]: https://github.com/quay/clair/compare/v4.0.0-rc.4...v4.0.0-rc.5
[v4.0.0-rc.4]: https://github.com/quay/clair/compare/v4.0.0-rc.3...v4.0.0-rc.4
[v4.0.0-rc.3]: https://github.com/quay/clair/compare/v4.0.0-rc.2...v4.0.0-rc.3
[v4.0.0-rc.2]: https://github.com/quay/clair/compare/v4.0.0-rc.1...v4.0.0-rc.2
[v4.0.0-rc.1]: https://github.com/quay/clair/compare/v4.0.0-alpha.7...v4.0.0-rc.1
[v4.0.0-alpha.7]: https://github.com/quay/clair/compare/v4.0.0-alpha.6...v4.0.0-alpha.7
[v4.0.0-alpha.6]: https://github.com/quay/clair/compare/v4.0.0-alpha.5...v4.0.0-alpha.6
[v4.0.0-alpha.5]: https://github.com/quay/clair/compare/v4.0.0-alpha.4...v4.0.0-alpha.5
[v4.0.0-alpha.4]: https://github.com/quay/clair/compare/v4.0.0-alpha.3...v4.0.0-alpha.4
[v4.0.0-alpha.3]: https://github.com/quay/clair/compare/v4.0.0-alpha.2...v4.0.0-alpha.3
