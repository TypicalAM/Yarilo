import os
dirname = os.path.dirname(__file__)

import RPi.GPIO as GPIO
import sys
sys.path.append(os.path.join(dirname, '..'))
import spidev as SPI
from lib import LCD_2inch4
from PIL import Image, ImageDraw, ImageFont

RST = 27
DC = 25
BL = 18
bus = 0
device = 0

BUTTON_PINS = {
    17: "ACCEPT",
    22: "REFUSE",
    26: "DOWN",
    13: "LEFT",
    6: "RIGHT",
    5: "UP"
}

def initialize_display():
    disp = LCD_2inch4.LCD_2inch4(spi=SPI.SpiDev(bus, device), spi_freq=10000000, rst=RST, dc=DC, bl=BL) 
    disp.Init()

    disp.command(0x36)
    disp.data(0x20)
    disp.clear()
    return disp

def display_message(disp, message):
    size = (320, 240)
    background = Image.new("RGB", size, (240, 255, 180))
    draw = ImageDraw.Draw(background)
    font = ImageFont.truetype(os.path.join(dirname, '../Font/Font01.ttf'), 25)

    bbox = draw.textbbox((0, 0), message, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    x = (size[0] - text_width) // 2
    y = (size[1] - text_height) // 2

    draw.text((x, y), message, fill="BLACK", font=font)
    disp.ShowImage(background.rotate(180))

try:
    GPIO.setmode(GPIO.BCM)
    for pin in BUTTON_PINS.keys():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

    disp = initialize_display()
    display_message(disp, "Press a button")

    while True:
        for pin, action in BUTTON_PINS.items():
            if GPIO.input(pin) == GPIO.HIGH:
                display_message(disp, f"{action} button pressed!")
except KeyboardInterrupt:
        disp.module_exit()
        exit()
