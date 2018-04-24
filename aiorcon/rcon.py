import asyncio
import traceback
import logging
from aiorcon.exceptions import RCONAuthenticationError, RCONError, RCONClosedError
from aiorcon.protocol import RCONProtocol
log = logging.getLogger(__name__)


class RCON:
    @classmethod
    async def create(cls, host, port, password, loop=None,
                     auto_reconnect_attempts=-1, auto_reconnect_delay=5, *,
                     multiple_packet=True, timeout=None):
        rcon = cls()
        rcon.host = host
        rcon.port = port
        rcon._loop = loop or asyncio.get_event_loop()
        rcon._auto_reconnect_attempts = auto_reconnect_attempts
        rcon._auto_reconnect_delay = auto_reconnect_delay
        rcon._creating_connection = None
        rcon._reconnecting = False
        rcon._closing = False

        def connection_lost():
            if rcon._auto_reconnect_attempts and not rcon._closing:
                rcon._reconnecting = asyncio.ensure_future(rcon._reconnect(), loop=rcon._loop)

        rcon.protocol_factory = lambda: RCONProtocol(password=password, loop=loop,
                                                     connection_lost_cb=connection_lost,
                                                     multiple_packet=multiple_packet, timeout=timeout)
        rcon.protocol = None

        await rcon._connect()
        return rcon

    async def _connect(self):
        _, protocol = await self._loop.create_connection(self.protocol_factory, self.host, self.port)
        await protocol.authenticate()
        self.protocol = protocol

    async def _reconnect(self):
        attempts = self._auto_reconnect_attempts
        while attempts:
            if self._auto_reconnect_attempts > 0:
                attempts -= 1
            try:
                await self._connect()
                return
            except RCONAuthenticationError:
                raise
            except (RCONError, OSError):
                if attempts == 0:
                    raise
                await asyncio.sleep(self._auto_reconnect_delay)

    async def __call__(self, command):
        try:
            return await self.protocol.execute(command)
        except RCONAuthenticationError:
            raise
        except RCONError:
            log.debug(traceback.format_exc())
            if self._reconnecting:
                await self._reconnecting
                return await self(command)
            else:
                raise

    def __getattr__(self, name):
        return getattr(self.protocol, name)

    def __repr__(self):
        return 'RCON(host=%r, port=%r, password=%r)' % (self.host, self.port, self.password)

    def close(self):
        """
        Close the connection transport
        """
        self._closing = True
        if self._reconnecting and not self._reconnecting.done():
            self._reconnecting.set_exception(RCONClosedError("The RCON connection was closed."))
        self.protocol.close()