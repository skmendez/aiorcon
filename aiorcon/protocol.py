import asyncio
import enum
import functools

from aiorcon.messages import ResponseBuffer, RCONMessage
from aiorcon.exceptions import RCONStateError, RCONTimeoutError, RCONAuthenticationError, \
                        RCONCommunicationError, RCONClosedError


class RCONProtocol(asyncio.Protocol):
    """Implements the RCON protocol"""

    class State(enum.IntEnum):
        CONNECTING, CONNECTED, AUTHENTICATED, CLOSED = range(4)

    def __init__(self, password, loop, connection_lost_cb=None, *, multiple_packet=True,
                 timeout=None, close_on_timeout=True):
        self.password = password
        self._loop = loop
        self._connection_lost_cb = connection_lost_cb
        self._multiple_packet = multiple_packet
        self._timeout = timeout
        self._close_on_timeout = close_on_timeout
        self.state = self.State.CONNECTING
        self._transport = None
        self.exc = None
        self._waiters = {}
        self._buffer = ResponseBuffer(self._multiple_packet)
        self._last_id = 0

    class EnsureState:
        def __init__(self, state):
            self._state = state

        def __call__(self, func):
            @functools.wraps(func)
            async def wrapper(instance, *args, **kwargs):
                if instance.state != self._state:
                    raise RCONStateError(self._state, instance.state)
                return await func(instance, *args, **kwargs)
            return wrapper

    @property
    def last_id(self):
        return self._last_id

    @last_id.setter
    def last_id(self, value):
        self._last_id = (value - 1) % (2 ** 31 - 1) + 1  # Keep values between 1 and 2**31-1

    @property
    def authenticated(self):
        return self.state == self.State.AUTHENTICATED

    @EnsureState(State.AUTHENTICATED)
    async def execute(self, command):
        """Executes command on connected RCON"""
        self.last_id += 1
        message = RCONMessage(self.last_id, RCONMessage.Type.EXECCOMMAND, command)
        self._write(message)
        if self._multiple_packet:
            self._write(RCONMessage.terminator(self.last_id))
        try:
            res = await asyncio.wait_for(self._receive(message.id), timeout=self._timeout)
        except asyncio.TimeoutError as e:
            if self._close_on_timeout:
                self.close()
            raise RCONTimeoutError from e
        return res.text

    @EnsureState(State.CONNECTED)
    async def authenticate(self):
        """Authenticates with RCON"""
        self._write(RCONMessage(0, RCONMessage.Type.AUTH, self.password))
        try:
            res = await self._receive()
        except ConnectionResetError:
            raise RCONAuthenticationError(True)

        self._buffer.clear()
        if res.id == -1:
            raise RCONAuthenticationError(False)
        self.state = self.State.AUTHENTICATED

    def close(self):
        """Closes RCON connection"""
        self._transport.close()
        self.state = self.State.CLOSED

    def _write(self, message):
        self._transport.write(message.encode())

    async def _receive(self, id_=None):
        self._waiters[id_] = self._loop.create_future()
        try:
            await self._waiters[id_]
            return self._buffer.pop(id_)
        except OSError as e:
            raise RCONCommunicationError from e
        finally:
            del self._waiters[id_]

    def connection_made(self, transport):
        self.state = self.State.CONNECTED
        self._transport = transport

    def connection_lost(self, exc):
        self.state = self.State.CLOSED
        self.exc = exc
        for waiter in self._waiters.values():
            if exc:
                waiter.set_exception(exc)
            else:
                waiter.set_exception(RCONClosedError("Connection closed before message was received"))
        if self._connection_lost_cb:
            self._connection_lost_cb()

    def data_received(self, data):
        cur_count = len(self._buffer.responses)
        self._buffer.feed(data)
        for id_, waiter in self._waiters.items():
            if id_ is None:
                if len(self._buffer.responses) > cur_count:
                    waiter.set_result(None)
            else:
                if id_ in self._buffer.responses and not waiter.cancelled():
                    if self._multiple_packet:
                        waiter.set_result(None)
                    else:
                        # Gives small amount of time for additional packets to accumulate
                        self._loop.call_later(1, waiter.set_result, None)