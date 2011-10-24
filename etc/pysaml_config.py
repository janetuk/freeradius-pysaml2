from saml2.saml import NAME_FORMAT_URI
from saml2 import BINDING_PAOS

# *** Change this line ***
BASE= "http://localhost:8088/"

# Don't change this line
BASEDIR = "/usr/local/etc/moonshot/"

CONFIG = {
    "entityid" : BASE + "metadata.xml",
    "description": "Radius SP",
    "service": {
        "sp":{
            "name" : "Radius SP",
            "endpoints":{
                "assertion_consumer_service": [BASE,
                                               (BASE+"ECP", BINDING_PAOS)],
            },
            # ** These you might want to change **
#            "required_attributes": ["surname", "givenName",
#                                    "eduPersonAffiliation"],
#            "optional_attributes": ["title"],
        }
    },
    "debug" : 0,
    "key_file" : BASEDIR + "pki/ssl.key",
    "cert_file" : BASEDIR + "pki/ssl.cert",
    "attribute_map_dir" : BASEDIR + "attributemaps",
    "metadata" : {
       "local": [BASEDIR + "metadata.xml"],
    },
    # in case xmlsec1 isn't anywhere normal
    "xmlsec_binary":"/opt/local/bin/xmlsec1",
    "name_form": NAME_FORMAT_URI,
    # -- below used by make_metadata --
    # ** These you probably want to change **
    "organization": {
        "name": "Exempel AB",
        "display_name": [("Exempel AB","se"),("Example Co.","en")],
        "url":"http://www.example.com/roland",
    },
    "contact_person": [{
        "given_name":"John",
        "sur_name": "Smith",
        "email_address": ["john.smith@example.com"],
        "contact_type": "technical",
        },
    ],
}
  
