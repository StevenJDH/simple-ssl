# Simple SSL

[![build](https://github.com/StevenJDH/simple-ssl/actions/workflows/maven-sonar-workflow.yml/badge.svg?branch=main)](https://github.com/StevenJDH/simple-ssl/actions/workflows/maven-sonar-workflow.yml)
![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/StevenJDH/simple-ssl?include_prereleases)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/48f1f6d78ce04a269402694189199fa3)](https://www.codacy.com/gh/StevenJDH/simple-ssl/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=StevenJDH/simple-ssl&amp;utm_campaign=Badge_Grade)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=StevenJDH_simple-ssl&metric=alert_status)](https://sonarcloud.io/dashboard?id=StevenJDH_simple-ssl)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=StevenJDH_simple-ssl&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=StevenJDH_simple-ssl)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=StevenJDH_simple-ssl&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=StevenJDH_simple-ssl)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=StevenJDH_simple-ssl&metric=sqale_index)](https://sonarcloud.io/dashboard?id=StevenJDH_simple-ssl)
[![Sonar Violations (long format)](https://img.shields.io/sonar/violations/StevenJDH_simple-ssl?format=long&server=https%3A%2F%2Fsonarcloud.io)](https://sonarcloud.io/dashboard?id=StevenJDH_simple-ssl)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=StevenJDH_simple-ssl&metric=security_rating)](https://sonarcloud.io/dashboard?id=StevenJDH_simple-ssl)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=StevenJDH_simple-ssl&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=StevenJDH_simple-ssl)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=StevenJDH_simple-ssl&metric=coverage)](https://sonarcloud.io/dashboard?id=StevenJDH_simple-ssl)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=StevenJDH_simple-ssl&metric=ncloc)](https://sonarcloud.io/dashboard?id=StevenJDH_simple-ssl)
![Maintenance](https://img.shields.io/maintenance/yes/2021)
![GitHub](https://img.shields.io/github/license/StevenJDH/simple-ssl)

Simple SSL is a lightweight library to easily create SSLContext instances from KeyStore and PEM files with different formats. Similar to how the native HttpClient works, the library makes use of the builder pattern to expose optional methods that can be used to customize a context without having to constantly rewrite the same blocks of code that would otherwise be required to do the same for many projects. With the resulting context, a secure connection can be established between a client and a server with or without mutual authentication (mTLS) to safeguard sensitive information.

[![Buy me a coffee](https://img.shields.io/static/v1?label=Buy%20me%20a&message=coffee&color=important&style=flat&logo=buy-me-a-coffee&logoColor=white)](https://www.buymeacoffee.com/stevenjdh)

Releases: [https://github.com/StevenJDH/simple-ssl/releases](https://github.com/StevenJDH/simple-ssl/releases)

## Features
* Load KeyStores/TrustStores in PKCS#12 and JKS formats (*.p12, *.pfx, *.jks, *.ks).
* Load Base64 encoded X.509 certificates and certificate chains (*.pem, *.crt, *.cer, *.pub).
* Load Base64 encoded X.509 private keys in PKCS#1 and PKCS#8 formats (*.pem, *.key).
* Certificate utilities for common tasks.
* Support for overriding to provide different implementations.

## Prerequisites
* Java 16 ([OpenJDK](https://adoptopenjdk.net))
* [Maven CLI](https://maven.apache.org)

## Installing the library
The following shows you how to set up a maven project to make use of this library **once it becomes available**.

### Add the dependency
Add the dependency to the project's `pom.xml` file like in any other maven project.

```xml
<dependency>
    <groupId>io.github.stevenjdh</groupId>
    <artifactId>simple-ssl</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Add GitHub's Apache Maven registry
Currently, the library is only available through GitHub's package registry, so you will need to specify it in the `repository` section of the project's `pom.xml` file.

```xml
<repositories>
    <repository>
        <id>github</id>
        <name>StevenJDH's GitHub Apache Maven Packages</name>
        <url>https://maven.pkg.github.com/StevenJDH/simple-ssl</url>
        <releases><enabled>true</enabled></releases>
        <snapshots><enabled>true</enabled></snapshots>
    </repository>
</repositories>
```

Access to the registry requires authentication to download the publicly available library. To set up the required access, add the following entry to your global `settings.xml` file located in the `%USERPROFILE%\.m2\` folder on Windows and in the `~/.m2/` directory on Linux.

``` xml
<servers>
    <server>
        <id>github</id>
        <username>YOUR_USERNAME</username>
        <password>YOUR_AUTH_TOKEN</password>
    </server>
</servers>
```

Replace `YOUR_USERNAME` with your GitHub login name, and replace `YOUR_AUTH_TOKEN` with a GitHub generated personal access token here _GitHub_ > _Settings_ > _Developer Settings_ > _Personal access tokens_ > _Generate new token_. The token needs to have at least the `read:packages` scope or you will get a `Not authorized` exception. For more information see [Working with the Apache Maven registry](https://help.github.com/en/articles/configuring-apache-maven-for-use-with-github-package-registry).

## Using the library
As the name implies, the use of the library is simple. See a few examples below to get started.

Generating the default SSLContext:

```java
var ctx = SimpleSSLContext.newSSLContext();
```

Creating an SSLContext from an existing keystore and or truststore using the default PKCS12 format:

```java
var ctx = SimpleSSLContext.newBuilder()
        .withKeyStore(path, "password")
        .withTrustStore(path, "password")
        .build();
```

Creating an SSLContext from a PEM file while changing the default format to JKS, and saving the result:

```java
var ctx = SimpleSSLContext.newPEMContextBuilder()
        .withPublicKey(path)
        .saveTrustStore(path, "password", KeyStoreType.JKS)
        .build();
```

Get a certificate's thumbprint in SHA-1 using one of the certificate utilities:

```java
String sha1 = CertUtil.getThumbprint(certificate, ":", HashType.SHA_1);
```

Programmatically access different git properties from when the library was built:

```java
String buildVersion = SimpleSSLContext.getBuildInfo().getGitBuildVersion();
```

### Working example
This example creates a custom SSLContext with a truststore for `https://untrusted-root.badssl.com` and applies it to a native HttpClient instance. To begin, download the certificate to trust with the following command as one approach:

```bash
openssl s_client -connect untrusted-root.badssl.com:443 > untrusted-root.badssl.com.cer
```

Create a maven project with the simple-ssl library added to it, and configure the `main` method with the following statements:

```java
public static void main(String[] args)
{
    var ctx = SimpleSSLContext.newPEMContextBuilder()
            .withPublicKey(Path.of("untrusted-root.badssl.com.cer"))
            .build();

    var client = HttpClient.newBuilder()
            .sslContext(ctx) // Comment this out to see it fail.
            .build();

    var request = HttpRequest.newBuilder()
            .uri(URI.create("https://untrusted-root.badssl.com"))
            .build();

    var response = client.send(request, BodyHandlers.ofString());

    System.out.println(response.body());
}
```

If all goes well, the connection should succeed since the untrusted certificate has been trusted in the truststore that was dynamically created from the supplied PEM formatted certificate. For more ideas around usage, have a look at the different unit and integration tests available in this repository.

## Contributing
Thanks for your interest in contributing! There are many ways to contribute to this project. Get started [here](https://github.com/StevenJDH/.github/blob/main/docs/CONTRIBUTING.md).

## Do you have any questions?
Many commonly asked questions are answered in the FAQ:
[https://github.com/StevenJDH/simple-ssl/wiki/FAQ](https://github.com/StevenJDH/simple-ssl/wiki/FAQ)

## Want to show your support?

|Method       | Address                                                                                                    |
|------------:|:-----------------------------------------------------------------------------------------------------------|
|PayPal:      | [https://www.paypal.me/stevenjdh](https://www.paypal.me/stevenjdh "Steven's Paypal Page")                  |
|Bitcoin:     | 3GyeQvN6imXEHVcdwrZwKHLZNGdnXeDfw2                                                                         |
|Litecoin:    | MAJtR4ccdyUQtiiBpg9PwF2AZ6Xbk5ioLm                                                                         |
|Ethereum:    | 0xa62b53c1d49f9C481e20E5675fbffDab2Fcda82E                                                                 |
|Dash:        | Xw5bDL93fFNHe9FAGHV4hjoGfDpfwsqAAj                                                                         |
|Zcash:       | t1a2Kr3jFv8WksgPBcMZFwiYM8Hn5QCMAs5                                                                        |
|PIVX:        | DQq2qeny1TveZDcZFWwQVGdKchFGtzeieU                                                                         |
|Ripple:      | rLHzPsX6oXkzU2qL12kHCH8G8cnZv1rBJh<br />Destination Tag: 2357564055                                        |
|Monero:      | 4GdoN7NCTi8a5gZug7PrwZNKjvHFmKeV11L6pNJPgj5QNEHsN6eeX3D<br />&#8618;aAQFwZ1ufD4LYCZKArktt113W7QjWvQ7CWDXrwM8yCGgEdhV3Wt|


// Steven Jenkins De Haro ("StevenJDH" on GitHub)
