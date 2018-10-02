#!/usr/bin/env python

from __future__ import print_function

import getpass
import sys
import re

from minecraft import authentication
from minecraft.exceptions import YggdrasilError
from minecraft.networking.connection import Connection
from minecraft.networking.packets import Packet, clientbound, serverbound
from minecraft.compat import input


def get_options():
    options = {}
        
    options["username"] = input("Enter your username: ")

    options["password"] = getpass.getpass("Enter your password: ")

    #options["address"] = input("Enter server: ")
    options["address"] = "localhost"
    options["port"] = 25565

    return options


def main():
    options = get_options()

    auth_token = authentication.AuthenticationToken()
    
    try:
        auth_token.authenticate(options["username"], options["password"])
    except YggdrasilError as e:
        print(e)
        sys.exit()
    print("Logged in as %s..." % auth_token.username)
    connection = Connection(
        options["address"], options["port"], auth_token=auth_token)

    def handle_join_game(join_game_packet):
        print('Connected.')

    connection.register_packet_listener(
        handle_join_game, clientbound.play.JoinGamePacket)

    def print_chat(chat_packet):
        print("Message (%s): %s" % (
            chat_packet.field_string('position'), chat_packet.json_data))

    connection.register_packet_listener(
        print_chat, clientbound.play.ChatMessagePacket)

    connection.connect()

    while True:
        try:
            text = input()
            if text == "/respawn":
                print("respawning...")
                packet = serverbound.play.ClientStatusPacket()
                packet.action_id = serverbound.play.ClientStatusPacket.RESPAWN
                connection.write_packet(packet)
            else:
                packet = serverbound.play.ChatPacket()
                packet.message = text
                connection.write_packet(packet)
        except KeyboardInterrupt:
            print("Bye!")
            sys.exit()


if __name__ == "__main__":
    main()
