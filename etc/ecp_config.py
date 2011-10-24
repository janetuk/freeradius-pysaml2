# You shouldn't change this line unless you know what you are doing
CONFIG = 'pysaml_config'                # PySAML2 Configuration file name
#IDENTITY_CACHE = "identity_cache"
#STATE_CACHE = "state_cache"

METADATA_FILE="../idp/idp.xml"

DEBUG=0

# Should the SP sign the request ?
SIGN=False

# This is needed in order to pick information about the right IdP from the
# metadata file. This must be the entity ID of the IdP not an endpoint
IDP_ENTITYID = "http://example.com/idp"

# Attribute filters per service@hostname
# the key are GSS-Acceptor-Service-Name+':'+GSS-Acceptor-Host-Name
# and the attribute names are the so called friendly-names

ATTRIBUTE_FILTER = {
    "ldap:example.com" : ["email", "givenName", "surname"],
}