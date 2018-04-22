import logging

from .rcon import RCON
from .exceptions import (RCONError, RCONAuthenticationError, RCONTimeoutError, RCONClosedError,
                         RCONCommunicationError, RCONMessageError, RCONStateError)
__version__ = '0.6.5'

log = logging.getLogger(__name__)
red_format = logging.Formatter('%(asctime)s %(levelname)s %(module)s %(funcName)s %(lineno)d: %(message)s',
                               datefmt="[%d/%m/%Y %H:%M]")
logging.basicConfig(format=red_format)
