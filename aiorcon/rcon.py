import asyncio
import logging
from aiorcon.exceptions import RCONAuthenticationError, RCONError, RCONClosedError
from aiorcon.protocol import RCONProtocol
log = logging.getLogger(__name__)


class RCON:
    @classmethod
    async def create(cls, host, port, password, loop=None,
                     auto_reconnect_attempts=-1, auto_reconnect_delay=5, *,
                     multiple_packet=True, timeout=None, auto_reconnect_cb=None):
        rcon = cls()
        rcon.host = host
        rcon.port = port
        rcon._loop = loop or asyncio.get_event_loop()
        rcon._auto_reconnect_attempts = auto_reconnect_attempts
        rcon._auto_reconnect_delay = auto_reconnect_delay
        rcon._auto_reconnect_cb = auto_reconnect_cb
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
        attempt = 0
        while attempt < self._auto_reconnect_attempts or self._auto_reconnect_attempts == -1:
            attempt += 1
            if self._auto_reconnect_cb:
                self._auto_reconnect_cb(attempt)
            try:
                await self._connect()
                self._auto_reconnect_cb(0)
                return
            except RCONAuthenticationError:
                self._auto_reconnect_cb(-1)
                raise
            except (RCONError, OSError):
                log.debug("Error:", exc_info=True)
                if attempt == self._auto_reconnect_attempts:
                    self._auto_reconnect_cb(-1)
                    raise
                await asyncio.sleep(self._auto_reconnect_delay)

    async def __call__(self, command):
        if self._reconnecting and self._reconnecting.done():
            self._reconnecting = False
        while True:
            try:
                return await self.protocol.execute(command)
            except RCONAuthenticationError:
                raise
            except RCONError:
                log.debug("Reconnecting due to error", exc_info=True)
                if self._reconnecting:
                    await self._reconnecting
                    self._reconnecting = False
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
