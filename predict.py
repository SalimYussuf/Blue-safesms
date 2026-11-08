"""Check one message.  Usage: python predict.py "message text"   (no argument = you are prompted)"""
import sys

from safesms import load, pretty

print(pretty(load().analyze(" ".join(sys.argv[1:]) or input("Message: "))))
