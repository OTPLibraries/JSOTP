# JSOTP

This module is part of a chain of OTP libraries all written in different languages. See https://github.com/OTPLibraries

A simple One Time Password (OTP) library in JavaScript

Compatible with Authy and Google Authenticator. Full support for QR code url is provided.


## Libraries Needed

No external libraries are required to use any version of JSOTP. However, only SHA1Hmac is included. SHA256 and SHA512 are very unsupported throughought everything.


## Configuration

Add the whole otp script into your project, or modify it to your namespace liking. Leave out the index.html file, as this is a test file.


## Description

This was actually a spawn off pyotp, but I would necessarily say the code was copied. Things in python aren't in JavaScript, therefore I had to make the methods myself. However, credits will go to the module for providing a guideline of what to do. [Here](https://github.com/pyotp/pyotp) you can find pyotp and realize how different it really is.


_____________

## License

This library is licensed under GNU General Public License v3.0.


## Usage

To use this library, pick either TOTP or HOTP then use the provided files - giving the functions what they need. The only thing you really need to pay attention is settings. Check out the test file, as it will tell you what the default requirements is for Google Authenticator, but you should always be using Authy (it is the most lenient).


## TODO

* Optimize the whole thing. The code was translated and is still very messy. Could probably use some improvements in the hacked areas.
* Add comments - there are NO comments, should match up to COTP's style
