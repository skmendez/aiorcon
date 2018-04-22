import logging

from .rcon import RCON
from .exceptions import (RCONError, RCONAuthenticationError, RCONTimeoutError, RCONClosedError,
                         RCONCommunicationError, RCONMessageError, RCONStateError)
__version__ = '0.6.4'

log = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%d-%m-%Y:%H:%M:%S',
                    level=logging.DEBUG)
