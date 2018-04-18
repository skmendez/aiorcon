import struct
import asyncio
import enum
import functools
from collections import OrderedDict, defaultdict
from .exceptions import *
__version__ = '0.4.0'


class RCONMessage(object):
    """Represents a RCON request or response."""

    ENCODING = "ascii"

    class Type(enum.IntEnum):
        """Message types corresponding to ``SERVERDATA_`` constants."""

        RESPONSE_VALUE = 0
        AUTH_RESPONSE = 2
        EXECCOMMAND = 2
        AUTH = 3

    def __init__(self, id_, type_, body_or_text):
        self.id = int(id_)
        self.type = self.Type(type_)
        if isinstance(body_or_text, bytes):
            self.body = body_or_text
        else:
            self.body = b""
            self.text = body_or_text

    def __repr__(self):
        return ("<{0.__class__.__name__} "
                "{0.id} {0.type.name} {1}B>").format(self, len(self.body))

    def __bytes__(self):
        return self.encode()

    @property
    def text(self):
        """Get the body of the message as Unicode.
        :raises UnicodeDecodeError: if the body cannot be decoded as ASCII.
        :returns: the body of the message as a Unicode string.
        .. note::
            It has been reported that some servers may not return valid
            ASCII as they're documented to do so. Therefore you should
            always handle the potential :exc:`UnicodeDecodeError`.
            If the correct encoding is known you can manually decode
            :attr:`body` for your self.
        """
        return self.body.decode(self.ENCODING)

    @text.setter
    def text(self, text):
        """Set the body of the message as Unicode.
        This will attempt to encode the given text as ASCII and set it as the
        body of the message.
        :param str text: the Unicode string to set the body as.
        :raises UnicodeEncodeError: if the string cannot be encoded as ASCII.
        """
        self.body = text.encode(self.ENCODING)

    def encode(self):
        """Encode message to a bytestring."""
        terminated_body = self.body + b"\x00\x00"
        size = struct.calcsize("<ii") + len(terminated_body)
        return struct.pack("<iii", size, self.id, self.type) + terminated_body

    @classmethod
    def decode(cls, buffer_):
        """Decode a message from a bytestring.
        This will attempt to decode a single message from the start of the
        given buffer. If the buffer contains more than a single message then
        this must be called multiple times.
        :raises MessageError: if the buffer doesn't contain a valid message.
        :returns: a tuple containing the decoded :class:`RCONMessage` and
            the remnants of the buffer. If the buffer contained exactly one
            message then the remaning buffer will be empty.
        """
        size_field_length = struct.calcsize("<i")
        if len(buffer_) < size_field_length:
            raise RCONMessageError(
                "Need at least {} bytes; got "
                "{}".format(size_field_length, len(buffer_)))
        size_field, raw_message = \
            buffer_[:size_field_length], buffer_[size_field_length:]
        size = struct.unpack("<i", size_field)[0]
        if len(raw_message) < size:
            raise RCONMessageError(
                "Message is {} bytes long "
                "but got {}".format(size, len(raw_message)))
        message, remainder = raw_message[:size], raw_message[size:]
        fixed_fields_size = struct.calcsize("<ii")
        fixed_fields, body_and_terminators = \
            message[:fixed_fields_size], message[fixed_fields_size:]
        id_, type_ = struct.unpack("<ii", fixed_fields)
        body = body_and_terminators[:-2]
        return cls(id_, type_, body), remainder

    @classmethod
    def terminator(cls, id_):
        """Message which follows a EXECCOMMAND to make the server send
        the terminating responses.
        :returns: an :class:`RCONMessage` which represents an empty
            ``RESPONSE_VALUE``"""
        return cls(id_, cls.Type.RESPONSE_VALUE, b"")


class _ResponseBuffer(object):
    """Utility class to buffer RCON responses.
    This class strictly handles multi-part responses and rolls them up
    into a single response automatically. The end of a multi-part response
    is indicated by an empty ``RESPONSE_VALUE`` immediately followed by
    another with a body of ``0x00010000``. In order to prompt a server to
    send these terminators an empty ``RESPONSE_VALUE`` must be *sent*
    immediately after an ``EXECCOMMAND``.
    https://developer.valvesoftware.com/wiki/RCON#Multiple-packet_Responses
    .. note::
        Multi-part responses are only applicable to ``EXECCOMAND`` requests.
    """
    PARTIAL_RESPONSE_CAP = 4096  # Value at which partial responses are pruned

    def __init__(self):
        self._buffer = b""
        self.responses = OrderedDict()
        self._partial_responses = defaultdict(list)

    def pop(self, id_=None):
        """Pop first received message from the buffer, or the message
        with the given id.
        :raises RCONError: if there are no whole complete in the buffer.
        :returns: the oldest response in the buffer as a :class:`RCONMessage`.
        """
        if not self.responses:
            raise RCONError("Response buffer is empty")
        if id_ is None:
            return self.responses.popitem()[1]
        else:
            return self.responses.pop(id_)

    def clear(self):
        """Clear the buffer.
        This clears the byte buffer, response buffer,  and partial response
        buffer.
        """
        self._buffer = b""
        self.responses.clear()
        self._partial_responses.clear()

    def _consume(self):
        """Attempt to parse buffer into responses.
        This may or may not consume part or the whole of the buffer.
        """
        while self._buffer:
            try:
                message, self._buffer = RCONMessage.decode(self._buffer)
            except RCONMessageError:
                return
            else:
                if message.type is message.Type.RESPONSE_VALUE:
                    id_partial = self._partial_responses[message.id]
                    id_partial.append(message)
                    if len(id_partial) >= 2:
                        penultimate, last = id_partial[-2:]
                        if (not penultimate.body
                                and last.body == b"\x00\x01\x00\x00"):
                            message = RCONMessage(
                                message.id,
                                RCONMessage.Type.RESPONSE_VALUE,
                                b"".join(part.body for part
                                         in id_partial[:-2]),
                            )
                            self.responses[message.id] = message
                            del id_partial[:]
                else:
                    self.responses[message.id] = message

    def feed(self, bytes_):
        """Feed bytes into the buffer."""
        self._buffer += bytes_
        self._consume()
        for response_list in self._partial_responses.values():
            if len(response_list) > _ResponseBuffer.PARTIAL_RESPONSE_CAP:
                del response_list[:]


def _ensure(state, value=True):
    """Decorator to ensure a connection is in a specific state.
    Use this to wrap a method so that it'll only be executed when
    certain attributes are set to ``True`` or ``False``. The returned
    function will raise :exc:`RCONError` if the condition is not met.
    Additionally, this decorator will modify the docstring of the
    wrapped function to include a sphinx-style ``:raises:`` directive
    documenting the valid state for the call.
    :param str state: the state attribute to check.
    :param bool value: the required value for the attribute.
    """

    def decorator(func):

        @functools.wraps(func)
        def wrapper(instance, *args, **kwargs):
            if getattr(instance, state) is not value:
                exc = RCONError("Must {} {}".format(
                    "be" if value else "not be", state))
                if hasattr(instance, 'exc'):
                    exc.__cause__ = instance.exc
                raise exc
            return func(instance, *args, **kwargs)

        if not wrapper.__doc__.endswith("\n"):
            wrapper.__doc__ += "\n"
        wrapper.__doc__ += ("\n:raises RCONError: {} {}.".format(
            "if not" if value else "if", state))
        return wrapper

    return decorator


class RCONProtocol(asyncio.Protocol):
    """Implements the RCON protocol"""

    def __init__(self, password, loop, connection_lost_cb=None):
        self.password = password
        self.connected = False
        self._authenticated = False
        self._connection_lost_cb = connection_lost_cb
        self._loop = loop
        self._transport = None
        self.exc = None
        self._waiters = {}
        self._buffer = _ResponseBuffer()
        self._last_id = 0
        self.test = 0

    @property
    def last_id(self):
        return self._last_id

    @last_id.setter
    def last_id(self, value):
        self._last_id = (value - 1) % (2 ** 31 - 1) + 1  # Keep values between 1 and 2**31-1

    @property
    def authenticated(self):
        return self._authenticated and self.connected

    @_ensure('connected')
    @_ensure('authenticated')
    async def execute(self, command):
        """Executes command on connected RCON"""
        self.last_id += 1
        message = RCONMessage(self.last_id, RCONMessage.Type.EXECCOMMAND, command)
        self._write(message)
        self._write(RCONMessage.terminator(self.last_id))
        res = await self._receive(message.id)
        return res.text

    @_ensure('connected')
    @_ensure('authenticated', False)
    async def authenticate(self):
        """Authenticates with RCON"""
        self._write(RCONMessage(0, RCONMessage.Type.AUTH, self.password))
        try:
            res = await self._receive()
        except ConnectionResetError:
            raise RCONAuthenticationError(True)

        self._buffer.clear()
        if res.id == -1:
            raise RCONAuthenticationError
        self._authenticated = True

    def close(self):
        """Closes RCON connection"""
        self._transport.close()
        self.connected = False

    def _write(self, message):
        self._transport.write(message.encode())

    async def _receive(self, id_=None):
        self._waiters[id_] = self._loop.create_future()
        try:
            await self._waiters[id_]
            return self._buffer.pop(id_)
        finally:
            del self._waiters[id_]

    def connection_made(self, transport):
        self.connected = True
        self._transport = transport

    def connection_lost(self, exc):
        self.connected = False
        self.exc = exc
        for waiter in self._waiters.values():
            if exc:
                waiter.set_exception(exc)
            else:
                waiter.cancel()
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
                if id_ in self._buffer.responses:
                    if not waiter.cancelled():
                        waiter.set_result(None)


class RCON:
    @classmethod
    async def create(cls, host, port, password, loop=None, auto_reconnect_attempts=-1, auto_reconnect_delay=5):
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
                                     connection_lost_cb=connection_lost)
        rcon.protocol = None

        await rcon._reconnect()
        return rcon

    async def _reconnect(self):
        attempts = self._auto_reconnect_attempts
        while attempts:
            if self._auto_reconnect_attempts > 0:
                attempts -= 1
            try:
                _, protocol = await self._loop.create_connection(self.protocol_factory, self.host, self.port)
                await protocol.authenticate()
                self.protocol = protocol
                return
            except OSError as e:
                print(repr(e))
                if attempts == 0:
                    raise
                await asyncio.sleep(self._auto_reconnect_delay)

    async def __call__(self, command):
        try:
            return await self.protocol.execute(command)
        except OSError as e:
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
        self.protocol.close()

