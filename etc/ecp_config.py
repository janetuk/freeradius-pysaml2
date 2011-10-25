# You shouldn't change this line unless you know what you are doing
CONFIG = 'pysaml_config'                # PySAML2 Configuration file name

METADATA_FILE="metadata.xml"

DEBUG=0

# Should the SP sign the request ?
SIGN=False

# This is needed in order to pick information about the right IdP from the
# metadata file. This must be the entity ID of the IdP not an endpoint
IDP_ENTITYID = "http://example.com/idp"

# The password that should be used when authenticating with the IdP
# This password will be used disregarding which user it is.
PASSWD = "foobar"