aiorcon
============

.. image:: https://img.shields.io/pypi/v/aiorcon.svg
    :target: https://pypi.org/project/aiorcon/

.. image:: https://img.shields.io/pypi/l/aiorcon.svg
    :target: https://pypi.python.org/pypi/aiorcon

.. image:: https://img.shields.io/pypi/pyversions/aiorcon.svg
    :target: https://pypi.python.org/pypi/aiorcon

An asynchronous interface for the Source RCON Protocol.

Installation
------------

The easiest way is to install via pip:

.. code-block::

    pip install aiorcon

Usage Example
-------------

Using aiorcon is pretty simple. First you have to create a RCON Object with
the `create` method. The RCON Object itself is now callable with the command
you want to send. After awaiting the call you get the output of the command.

.. code-block:: python

  import aiorcon
  import asyncio

  async def main(loop):

      # initialize the RCON connection with ip, port, password and the event loop.
      rcon = await aiorcon.RCON.create("192.168.2.137", 27015, "rconpassword", loop)

      # send a command
      stats = await(rcon("stats"))
      print(stats)

      # close the connection in the end
      rcon.close()

  loop = asyncio.get_event_loop()
  loop.run_until_complete(main(loop))
