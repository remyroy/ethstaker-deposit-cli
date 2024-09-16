# Release Process Instructions

This document is meant as a guide on how to perform and publish a new release version of ethstaker-deposit-cli. It includes step by step instructions to complete the release process.

1. Determine a new version number. Version numbers should adhere to [Semantic Versioning](https://semver.org/). For any official release, it should include a major, a minor and a patch identifier like `1.0.0`.
2. Update `ethstaker_deposit/__init__.py`'s `__version__` variable with the new version number. Commit this change to the main branch of the main repository.
3. Add a tag to the main repository for this changed version commit above. The name of this tag should be a string starting with `v` concatenated with the version number. With git and the main repository cloned, it can look like this:
```console
git tag -a -m 'Version 1.0.0' v1.0.0
git push origin v1.0.0
```
4. Wait for [the ci-runner](https://github.com/eth-educators/ethstaker-deposit-cli/actions/workflows/runner.yml) tests to complete for this new tag. Make sure all tests are passing on all the supported platforms.
5. Start the build process to create the application binaries. Run [the ci-build workflow](https://github.com/eth-educators/ethstaker-deposit-cli/actions/workflows/build.yml) from the tag you created at step 3.
6. Wait for all the build assets to be created. Wait for the docker image to be created by the ci-docker workflow.
7. Draft [a new release on Github](https://github.com/eth-educators/ethstaker-deposit-cli/releases/new).
8. Choose the tag you created at step 3.
9. Click the *Generate release notes* button. Copy the generated content to be included later.
10. Add an interesting release title.
11. Use [the template below](#release-notes-template) for the content of the release notes. Fill in the different sections correctly. Make sure all the links are updated to work with the new release including the various asset links and the docker image link. Include the generated release notes from step 9 in the *All changes* section.
12. Download all the release assets from [the build process](https://github.com/eth-educators/ethstaker-deposit-cli/actions/workflows/build.yml) in step 5. Extract the zip files to get the actual release files. Upload them all in the draft release binaries section.
13. If this is not a production release, check the *Set as a pre-release* checkbox.
14. Click the *Publish release* button.
15. Determine a new dev version number. You can try to guess the next version number to the best of your ability. This will always be subject to change. Add a `dev` identifier to the version number to clearly indicate this is a dev version number.
16. Update `ethstaker_deposit/__init__.py`'s `__version__` variable with a new dev version number. Commit this change to the main branch.

It's probably a good idea to download some of the binary assets and see if you can perform one or two of the commands on your platform of choice just to make sure there is not major issue with them.

## Release Notes Template

You can start the release notes with this template:

```markdown
# Summary

This preview release contains all the changes that were made since the original fork of the [staking-deposit-cli project](https://github.com/ethereum/staking-deposit-cli/) ([fdab65d commit](https://github.com/ethereum/staking-deposit-cli/commit/fdab65d33a63632e1935e9a9235119a46e37c221)).

Notable changes from the original project include:

- New exit commands to create an exit message and perform a voluntary exit for your validators.
- Multiprocessing support to increase the speed of processes that can be expanded to use more than a single thread or a single process. This helps with generating a large number of validator keys for instance.
- Support for more recent OSes and Python versions by default.
- A dedicated [documentation website](https://eth-educators.github.io/ethstaker-deposit-cli/).

# Known Issues

`[Remove this section if there is no known issue]`

# All changes

`[Generated release notes]`

# Building process

Release assets were built using Github Actions and [this workflow run](https://github.com/eth-educators/ethstaker-deposit-cli/actions/runs/10113717389). You can establish the provenance of this build using [our artifact attestations](https://github.com/eth-educators/ethstaker-deposit-cli/attestations).

# Binaries

Our binaries are signed with ethstaker-deposit-cli's PGP key: `54FA06FC0860FC0DCCC68E3ECE9FF2391DF26368` .

| System  | Architecture | Binary             | Checksum               | PGP Signature         |
|---------|--------------|--------------------|------------------------|-----------------------|
| Windows | x86_64       | [ethstaker_deposit-cli-c840111-windows-amd64.zip](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-windows-amd64.zip) | [sha256](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-windows-amd64.zip.sha256) | [PGP Signature](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-windows-amd64.zip.asc) |
| macOS   | x86_64       | [ethstaker_deposit-cli-c840111-darwin-amd64.tar.gz](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-darwin-amd64.tar.gz) | [sha256](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-darwin-amd64.tar.gz.sha256) | [PGP Signature](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-darwin-amd64.tar.gz.asc) |
| macOS   | aarch64      | [ethstaker_deposit-cli-c840111-darwin-arm64.tar.gz](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-darwin-arm64.tar.gz) | [sha256](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-darwin-arm64.tar.gz.sha256) | [PGP Signature](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-darwin-arm64.tar.gz.asc) |
| Linux   | x86_64       | [ethstaker_deposit-cli-c840111-linux-amd64.tar.gz](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-linux-amd64.tar.gz) | [sha256](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-linux-amd64.tar.gz.sha256) | [PGP Signature](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-linux-amd64.tar.gz.asc) |
| Linux   | aarch64      | [ethstaker_deposit-cli-c840111-linux-arm64.tar.gz](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-linux-arm64.tar.gz) | [sha256](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-linux-arm64.tar.gz.sha256) | [PGP Signature](https://github.com/eth-educators/ethstaker-deposit-cli/releases/download/v0.1.0/ethstaker_deposit-cli-c840111-linux-arm64.tar.gz.asc) |

# Docker image

| Version | Name | Package |
|---------|------|---------|
| v0.1.0  | `ghcr.io/eth-educators/ethstaker-deposit-cli:v0.1.0` | [Github Package](https://github.com/eth-educators/ethstaker-deposit-cli/pkgs/container/ethstaker-deposit-cli/249338184?tag=v0.1.0) |

## License

By downloading and using this software, you agree to the [license](LICENSE).
```