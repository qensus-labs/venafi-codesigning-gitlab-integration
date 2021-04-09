# Maintenance guide

## Releasing a new version

> See also the [internal development notes](https://gitlab.fullstaq.systems/venafi/dev-notes/blob/master/VENAFI-CLIENT-TOOLS.md) to learn how to check for and obtain new Venafi client tools versions.

 1. Determine the version numbers of the latest 4 Venafi client tools minor versions (see the [Image versioning policy](README.md#image-versioning-policy)). Update the `VENAFI_CLIENT_TOOL_VERSIONS` specification in `.github/workflows/ci-cd.yml` accordingly.

 2. Ensure that all these Venafi client tools versions are stored in [Azure Blob Storage](https://portal.azure.com/#blade/Microsoft_Azure_Storage/ContainerMenuBlade/overview/storageAccountId/%2Fsubscriptions%2Fb09e5a51-eff8-4405-9a58-d1966ceae565%2Fresourcegroups%2Fci-cd%2Fproviders%2FMicrosoft.Storage%2FstorageAccounts%2Ffsvenafigitlabcicd/path/venafi-client-tools/etag/%220x8D8F995EF6E0B0F%22/defaultEncryptionScope/%24account-encryption-key/denyEncryptionScopeOverride//defaultId//publicAccessVal/None).

    When uploading, beware of these:

     * Ensure version numbers are removed from filenames.

        - Rename `Venafi Code Signing Clients vX.X.X.dmg` to `Venafi Code Signing Clients.dmg`
        - Rename `venafi-codesigningclients-X.X.X-linux-x86_64.rpm` to `venafi-codesigningclients-linux-x86_64.rpm`

     * Access tier: Cool.
     * Set the directory equal to the full Venafi client tools version, including patch version. For example: `20.4.0`

 3. Ensure [the CI](https://github.com/fullstaq-labs/venafi-codesigning-gitlab/actions) is successful.

 4. [Manually run the "CI/CD" workflow](https://github.com/fullstaq-labs/venafi-codesigning-gitlab/actions/workflows/ci-cd.yml). Set the `create_release` parameter to `true`. Wait until it finishes. This creates a draft release.

 5. Edit [the draft release](https://github.com/fullstaq-labs/venafi-codesigning-gitlab/releases)'s notes and finalize the release.
