# You shouldn't change this line unless you know what you are doing
CONFIG = 'pysaml_config'                # PySAML2 Configuration file name

METADATA_FILE="/usr/local/etc/moonshot/metadata.xml"

DEBUG=0

# Should the SP sign the request ?
SIGN=False

# This is needed in order to pick information about the right IdP from the
# metadata file. This must be the entity ID of the IdP not an endpoint
IDP_ENTITYID = "http://example.com/idp"

# The password that should be used when authenticating with the IdP
# This password will be used disregarding which user it is.

PASSWD = ""

# If you don't want to used Basic-Auth you can place the username in a
# header. This defines the header name

USERNAME_HEADER = "X-Moonshot-Username"

# is the path of a file containing root CA certificates for SSL
# server certificate validation.

CA_CERTS = ""

# If disable_ssl_certificate_validation is true, SSL cert validation will
# not be performed.

DISABLE_SSL_CERTIFICATE_VALIDATION = True