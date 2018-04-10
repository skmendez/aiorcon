__version__ = '0.1.1'

import struct
import asyncio
import enum
import functools
from collections import OrderedDict


class RCONError(Exception):
    """Base exception for all RCON-related errors."""


class RCONCommunicationError(RCONError):
    """Used for propagating socket-related errors."""


class RCONTimeoutError(RCONError):
    """Raised when a timeout occurs waiting for a response."""


class RCONAuthenticationError(RCONError):
    """Raised for failed authentication.
    :ivar bool banned: signifies whether the authentication failed due to
        being banned or for merely providing the wrong password.
    """

    def __init__(self, banned=False):
        super(RCONError, self).__init__(
            "Banned" if banned else "Wrong password")
        self.banned = banned


class RCONMessageError(RCONError):
    """Raised for errors encoding or decoding RCON messages."""


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
    def terminator(cls):
        """Message which follows a EXECCOMMAND to make the server send
        the terminating responses.
        :returns: an :class:`RCONMessage` which represents an empty
            ``RESPONSE_VALUE``"""
        return cls(0, cls.Type.RESPONSE_VALUE, b"")


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
    In addition to handling multi-part responses transparently this class
    provides the ability to :meth:`discard` incoming messages. When a
    message is discarded it will be parsed from the buffer but then
    silently dropped, meaning it cannot be retrieved via :meth:`pop`.
    Message discarding works with multi-responses but it only applies to
    the complete response, not the constituent parts.
    """

    def __init__(self):
        self._buffer = b""
        self.responses = OrderedDict()
        self._partial_responses = []
        self._discard_count = 0

    def pop(self, id_=None):
        """Pop first received message from the buffer, or the message
        with the given id.
        :raises RCONError: if there are no whole complete in the buffer.
        :returns: the oldest response in the buffer as a :class:`RCONMessage`.
        """
        if not self.responses:
            raise RCONError("Response buffer is empty")
        if id_ is None:
            return self.responses.popitem[1]
        else:
            return self.responses.pop(id_)

    def clear(self):
        """Clear the buffer.
        This clears the byte buffer, response buffer, partial response
        buffer and the discard counter.
        """
        self._buffer = b""
        self.responses.clear()
        del self._partial_responses[:]
        self._discard_count = 0

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
                    self._partial_responses.append(message)
                    if len(self._partial_responses) >= 2:
                        penultimate, last = self._partial_responses[-2:]
                        if (not penultimate.body
                                and last.body == b"\x00\x01\x00\x00"):
                            message = RCONMessage(
                                self._partial_responses[0].id,
                                RCONMessage.Type.RESPONSE_VALUE,
                                b"".join(part.body for part
                                         in self._partial_responses[:-2]),
                            )
                            self.responses[message.id] = message
                            del self._partial_responses[:]
                else:
                    self.responses[message.id] = message

    def feed(self, bytes_):
        """Feed bytes into the buffer."""
        self._buffer += bytes_
        self._consume()


def _ensure(state, value=True):  # pylint: disable=no-self-argument
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
                if instance.exc:
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

    def __init__(self, password, loop, timeout=3):
        self.password = password
        self.connected = False
        self.authenticated = False
        self.timeout = timeout
        self._loop = loop
        self._transport = None
        self.exc = None
        self._waiters = {}
        self._buffer = _ResponseBuffer()
        self._reqid = 0

    @property
    def reqid(self):
        return self._reqid

    @reqid.setter
    def reqid(self, value):
        self._reqid = (value - 1) % (2**31 - 1) + 1  # Keep values between 1 and 2**31-1

    @_ensure('connected')
    @_ensure('authenticated')
    async def execute(self, command):
        """Executes command on connected RCON"""
        self.reqid += 1
        message = RCONMessage(self.reqid, RCONMessage.Type.EXECCOMMAND, command)
        self._write(message)
        self._write(RCONMessage.terminator())
        res = await self._receive(message.id)
        return res.text

    @_ensure('connected')
    @_ensure('authenticated', False)
    async def authenticate(self):
        """Authenticates with RCON"""
        self._write(RCONMessage(0, RCONMessage.Type.AUTH, self.password))
        possible_reponses = (self._receive(0), self._receive(-1))
        done_task, pending_task = await asyncio.wait(possible_reponses, return_when=asyncio.FIRST_COMPLETED)
        pending_task.pop().cancel()
        res = done_task.pop().result()
        self._buffer.clear()
        if res.id == -1:
            raise RCONAuthenticationError
        self.authenticated = True

    @_ensure('connected')
    def close(self):
        """Closes RCON connection"""
        self._transport.close()
        self.connected = False

    def _write(self, message):
        self._transport.write(message.encode())

    async def _receive(self, id_):
        self._waiters[id_] = self._loop.create_future()
        try:
            await self._waiters[id_]
            return self._buffer.pop(id_)
        except asyncio.CancelledError:
            return
        finally:
            del self._waiters[id_]

    def connection_made(self, transport):
        self.connected = True
        self._transport = transport

    def connection_lost(self, exc):
        self.connected = False
        self.exc = exc

    def data_received(self, data):
        self._buffer.feed(data)
        for id_, waiter in self._waiters.items():
            if id_ in self._buffer.responses:
                if not waiter.cancelled():
                    waiter.set_result(None)

    @classmethod
    async def new_connection(cls, host, port, password, loop, timeout=3):
        fut = loop.create_connection(lambda: cls(password, loop, timeout), host, port)
        try:
            _, protocol = await asyncio.wait_for(fut, timeout, loop=loop)
        except Exception as cause:
            raise RCONCommunicationError("Connecting to server failed") from cause
        await protocol.authenticate()
        return protocol