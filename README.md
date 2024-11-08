# ca-cipher-check
Check the CA key cipher is AES


Welcome!

In order to use this script you will need two archives:
* All the versions of Easy-RSA that you want to test.
  Default directory: ./ | Search term: EasyRSA-*
* All the versions of OpenSSL that you want to test.
  Default directory: ./ | Search term: openssl-*
You can only define the directory not the search term.

To define a different location for these archives,
'export' the variables 'ERSA_ARC_D' and 'OSSL_ARC_D',
to point to the Easy-RSA archive and OpenSSl archive,
respectively.

To force all tests to be executed use option 'all'.
This will force some user interaction for passwords.
ALWAYS use password 'pppp' for user interaction.

Use option 'keep' to keep all the created PKIs, for
further inspection.

Press [enter] to continue.

