# Concrete5 Package for LDAP Login
This Package provides a LDAP login AuthenticationType for Concrete5 5.7 with Yubikey two-factor support. By default the Yubikey two-factor support is disabled and is not need for environments, where you just want to authenticate against a LDAP server. The package uses the Yubikey OTP mechanism to create a second factor for authentication. By default is verifies the OTPs with the YubiCloud service from Yubico, which requires an API key form them. (Grab it [here](https://upgrade.yubico.com/getapikey/).) For verifying the OTPs it uses the [php-yubico](https://developers.yubico.com/php-yubico/) library, which is bundled in this package. The key id is also gathered via LDAP.

##License
Concrete5 Package for LDAP Login  
Copyright (C) 2015  Christoph Seitz

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

The AuthYubico.php file and the yubiright_16x16.gif file are licensed under a BSD license. See the file library/authentication/COPYING for exact wording. For any copyright year range specified as YYYY-ZZZZ in this package note that the range specifies every single year in that closed interval.

## Requierments
The folloging debian packages are required before installing this concrete package.
 * php5-ldap
 * php5-curl
 * php-pear

##Configuration
Both the LDAP authentication and the Yubikey OTP authentication are fully configurable.
### LDAP Configuration
**LDAP Server URI**  
The complete LDAP Server URI.  
*Example:* ldaps://ldap.example.de

**LDAP Bind DN**  
The DN for initial binding with the server. Leave it blank for anonymous binding.  
*Example:* cn=ldap_login,dc=example,dc=com

**LDAP Bind Password**
The password for the bind DN. An empty password forces the server to do an anonymous bind.

**LDAP Base DN**
The base DN for the LDAP search. Enter a valid DN here to limit the search to a subtree in the directory.  
*Example:* ou=People,dc=example,dc=com

**LDAP Search Filter**
The search filter to use for finding users in the directory. The filter string uses the %u placeholder for the username. Only the first entry returned from the directory will be used for authentication.  
*Example:* (uid=%u)

### Yubikey OTP Configuration
**Enable Yubikey OTP**  
Enables the Yubikey OTP two-factor authentication.

**Yubikey Client ID**  
The client ID for the valdiation server.

**Yubikey Secret Key**  
The secret key for validation of client server communication. The communication is validated with hmac-sha1 algorithm. You can leave this blank. By default the code uses https connection, which doesn't require an extra validation.

**Yubikey Verify URI**  
The complete URI (server+path) to the verification server. You can leave this blank and use the default Yubicloud server.

**Yubikey Key ID LDAP Attribute**  
The LDAP Attribute to look for the key id. If there are multiple values for the attribute, all values will used for checking the key id.  
*Example:* pager

**Allow login with no Yubikey specified**  
Allow user, who have no yubikey key id in the LDAP directory speciefied, to login without OTPs.
