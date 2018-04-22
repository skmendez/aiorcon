import enum
import functools
import operator
import struct
from collections import OrderedDict, defaultdict

from aiorcon.exceptions import RCONMessageError, RCONError


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

    def __str__(self):
        return self.text

    def __bytes__(self):
        return self.encode()

    def __add__(self, other):
        if self.id != other.id:
            raise ValueError("IDs must be equal")
        if self.type != other.type:
            raise ValueError("Message type must be equal")

        return RCONMessage(self.id, self.type, self.body + other.body)

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


class ResponseBuffer(object):
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

    def __init__(self, multiple_packet=True):
        self._buffer = b""
        self.responses = OrderedDict()
        self._partial_responses = defaultdict(list)
        self.multiple_packet = multiple_packet

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
                    if self.multiple_packet:
                        id_partial = self._partial_responses[message.id]
                        id_partial.append(message)
                        if len(id_partial) >= 2:
                            penultimate, last = id_partial[-2:]
                            if (not penultimate.body
                                    and last.body == b"\x00\x01\x00\x00"):
                                message = functools.reduce(operator.add, id_partial[:-2])
                                self.responses[message.id] = message
                                del id_partial[:]
                    else:
                        if message.id in self.responses:
                            self.responses[message.id] += message
                        else:
                            self.responses[message.id] = message
                else:
                    self.responses[message.id] = message

    def feed(self, bytes_):
        """Feed bytes into the buffer."""
        self._buffer += bytes_
        self._consume()
        for response_list in self._partial_responses.values():
            if len(response_list) > ResponseBuffer.PARTIAL_RESPONSE_CAP:
                del response_list[:]