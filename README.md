# Venafi CodeSign Protect: Gitlab integration

This product integrates [Venafi CodeSign Protect](https://www.venafi.com/platform/code-signing) with Gitlab-based CI/CD processes.

Venafi CodeSign Protect is a solution for securing machines against attacks and exploits, by signing executables, libraries and other machine runtime artifacts with digital signatures. Unlike naive methods of code signing, Venafi CodeSign Protect is more secure, by storing and securing the signing key separately from the CI/CD infrastructure (perhaps even in a Hardware Security Module) and by providing access control to signing keys. It also provides important insights to security teams, such as how and when signing keys are used.

This plugin allows one to sign and verify files through Venafi CodeSign Protect. The following signing tools are supported:

 * Jarsigner (Java)
 * Signtool (Windows)

**Table of contents**

 - [Usage overview](#usage-overview)
 - [Prerequisites](#prerequisites)
    - [Executor host setup (shell and SSH executors only)]()
 - [Compatibility](#compatibility)
 - [Usage](#usage)
 - [Contribution & development]()

## Usage overview

You must already have access to one or more Venafi Trust Protection Platforms™ (TPPs). This Gitlab integration product requires you to specify TPP address and authentication details.

You use this Gitlab integration product by defining, inside your Gitlab CI YAML, steps that perform signing or verification. These steps consume artifacts generated by previous stages (such as unsinged .jar files), and may output artifacts that you can use in later stages (such as signed .jar files).

## Setting up executor hosts (shell and SSH executors only)

If you plan on using this Gitlab integration product in combination with the shell and SSH executors, then you must install the following software on the hosts on which those executors operate. This Gitlab integration product does not take care of installing these prerequisites for you.

 * Install Venafi CodeSign Protect client tools (see [Compatibility](#compatibility) to learn which versions are supported)
    - You do *not* need to *configure* the client tools (i.e. they don't need to be configured with a TPP address or credentials). They just need to be installed. This Gitlab integration product will take care of configuring the client tools with specific TPPs.
 * Install Python >= 3.7. Ensure that it's in PATH.
 * Install our Gitlab integration package: `pip install venafi-codesigning-gitlab-integration`

## Compatibility

This product is compatible with:

 * Trust Protection Platform 20.2 or later.
 * Venafi CodeSign Protect client tools 20.2 or later.

This product supports the following Gitlab runner executors:

 * Shell
 * SSH
 * Docker

## Usage

### Sign with Jarsigner

This section shows how to sign one or more files with Java's [Jarsigner](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html) tool. It assumes that jarsigner is in PATH.

#### Docker executor

 * Define a job that calls `venafi-sign-jarsigner`.
 * Ensure the job operates within the image `quay.io/fullstaq-venafi-codesigning-gitlab-integration/jarsigner-x86_64`.
 * Set the `INPUT_PATH` variable to the file that you wish to sign.
 * Set other required variables too. See the variables reference below.

~~~yaml
stages:
  - build
  - sign

# Build a 'foo.jar' and pass it as an artifact to the 'sign' stage.
build_jar:
  stage: build
  script:
    - echo 'public class Foo { public static void main() { } }' > Foo.java
    - javac Foo.java
    - jar -cf foo.jar Foo.class
  artifacts:
    paths:
      - foo.jar

# Sign the 'foo.jar' that was generated by the 'build' stage,
# then store the signed jar as an artifact.
sign_jarsigner:
  stage: sign
  image:
    name: quay.io/fullstaq-venafi-codesigning-gitlab-integration/jarsigner-x86_64
  script:
    - venafi-sign-jarsigner
  variables:
    TPP_AUTH_URL: https://my-tpp/vedauth
    TPP_HSM_URL: https://my-tpp/vedhsm
    TPP_USERNAME: my_username
    # TPP_PASSWORD should be set in the UI, with masking enabled.

    INPUT_PATH: foo.jar
    CERTIFICATE_LABEL: my label
  artifacts:
    paths:
      - foo.jar
~~~

### Shell or SSH executor

 * Define a job that calls `venafi-sign-jarsigner`.
 * Set the `INPUT_PATH` variable to the file that you wish to sign.
 * Set other required variables too. See the variables reference below.

~~~yaml
stages:
  - build
  - sign

# Build a 'foo.jar' and pass it as an artifact to the 'sign' stage.
build_jar:
  stage: build
  script:
    - echo 'public class Foo { public static void main() { } }' > Foo.java
    - javac Foo.java
    - jar -cf foo.jar Foo.class
  artifacts:
    paths:
      - foo.jar

# Sign the 'foo.jar' that was generated by the 'build' stage,
# then store the signed jar as an artifact.
sign_jarsigner:
  stage: sign
  script:
    - venafi-sign-jarsigner
  variables:
    TPP_AUTH_URL https://my-tpp/auth
    TPP_HSM_URL: https://my-tpp/hsm
    TPP_USERNAME: my_username
    # TPP_PASSWORD should be set in the UI, with masking enabled.

    INPUT_PATH: foo.jar
    CERTIFICATE_LABEL: my label
  artifacts:
    paths:
      - foo.jar
~~~

### Variables

Required:

 * `TPP_AUTH_URL`: The TPP's authorization URL.
 * `TPP_HSM_URL`: The TPP's Hardware Security Module (HSM) backend URL.
 * `TPP_USERNAME`: A login username for the TPP.
 * `TPP_PASSWORD`: The password associated with the login username.
 * `INPUT_PATH` or `INPUT_GLOB`: Specifies the file(s) to sign, either through a single filename, or a glob.
 * `CERTIFICATE_LABEL`: The label of the certificate (inside the TPP) to use for code signing. You can obtain a list of labels with `pkcs11config listcertificates`.

Optional:

 * `TIMESTAMPING_SERVERS`: Specifies one or more timestamping authority servers to use during signing. Specifying this is strongly recommended, because it allows signed files to be usable even after the original signing certificate has expired.

    If you specify more than one server, then a random one will be used.

    Example:

    ~~~
    TIMESTAMPING_SERVERS: http://server1,http://server2
    ~~~

    **Tip:** here are some public timestamping authorities that you can use:

     - http://timestamp.digicert.com
     - http://timestamp.globalsign.com
     - http://timestamp.comodoca.com/authenticode
     - http://tsa.starfieldtech.com

 * `EXTRA_ARGS`: Specifies extra custom CLI arguments to pass to Jarsigner. The arguments are comma-separated.

    These arguments will be _appended_ to the Jarsigner CLI invocation, and take precedence over any arguments implicitly passed by this plugin.

    Example:

    ~~~
    EXTRA_ARGS: -arg1,-arg2
    ~~~

 * `VENAFI_CLIENT_TOOLS_DIR`: Specifies the path to the directory in which Venafi CodeSign Protect client tools are installed. If not specified, it's autodetected as follows:

     - Linux: /opt/venafi/codesign
     - macOS: /Library/Venafi/CodeSigning
     - Windows: autodetected from the registry, or (if that fails): C:\Program Files\Venafi CodeSign Protect

## Contribution & development

See the [contribution guide](CONTRIBUTING.md).
