Image size issues for Burp Suite
================================

[![Build Status](https://travis-ci.org/silentsignal/burp-image-size.svg?branch=master)](https://travis-ci.org/silentsignal/burp-image-size)

When serving image assets, many web developers find it useful to have a
feature that scales the image to a size specified in a URL parameter.
Such functionality can not only be used for scaling images **down** but
also making them huge, this leads to Denial of Service (DoS). This Burp
plugin that can be loaded into Extender, and passively detects if the
size of an image reply is included in the request parameters.

Read more in [our blog post about this plugin](https://blog.silentsignal.eu/2016/02/10/youre-not-looking-at-the-big-picture/)

Building
--------

 - (For testing) install JUnit, put the JARs into `lib`
 - Execute `ant`, and you'll have the plugin ready in `burp-image-size.jar`

Dependencies
------------

 - JDK 1.6+ (tested on OpenJDK 6 and Oracle JDK 7 + 8, recommended Debian/Ubuntu package: `openjdk-8-jdk`)
 - Apache ANT (Debian/Ubuntu package: `ant`)
 - JUnit 4+ (only required for testing)

License
-------

The whole project is available under MIT license, see `LICENSE.txt`.
