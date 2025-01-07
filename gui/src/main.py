import os
import RPi.GPIO as GPIO
import sys
from time import sleep, time
dirname = os.path.dirname(__file__)
sys.path.append(os.path.join(dirname, '..'))
from PIL import Image, ImageDraw, ImageFont
import spidev as SPI
from lib import LCD_2inch4
import client
import textwrap

# Constants
RST = 27
DC = 25
BL = 18
bus = 0
device = 0
fontsize = 25

BUTTON_PINS = {
    17: "ACCEPT",
    22: "REFUSE",
    26: "DOWN",
    13: "LEFT",
    6: "RIGHT",
    5: "UP"
}

class Display:
    def __init__(self):
        self.disp = LCD_2inch4.LCD_2inch4(spi=SPI.SpiDev(bus, device), spi_freq=10000000, rst=RST, dc=DC, bl=BL)
        self.disp.Init()
        self.disp.command(0x36)
        self.disp.data(0x20)
        self.disp.clear()
        self.in_menu = False
        self.scrollable = False
        self.scroll_offset = 0
        self.current_message = None
        self.current_color = "BLACK"
        self.current_lines = []
        self.current_font = None
        self.current_y = 0
        self.current_text_height = 0

    def show_message(self, message, color="BLACK"):
        self.in_menu = False
        self.scrollable = False
        self.current_message = message
        self.current_color = color
        size = (320, 240)
        background = Image.new("RGB", size, (240, 255, 180))
        draw = ImageDraw.Draw(background)
        font = ImageFont.truetype(os.path.join(os.path.dirname(__file__), '../Font/Font02.ttf'), fontsize)
        self.current_font = font

        max_width = size[0]
        wrapped_text = textwrap.fill(message, width=max_width // fontsize * 2)

        lines = wrapped_text.split('\n')
        self.current_lines = lines
        text_height = sum([fontsize for line in lines])
        self.current_text_height = text_height

        y = (size[1] - text_height) // 2
        self.current_y = y

        if text_height > size[1]:
            self.scrollable = True
            self.draw_text()
        else:
            self.scrollable = False
            y_offset = y
            for line in lines:
                draw.text((5, y_offset), line, fill=color, font=font)
                y_offset += fontsize
            self.disp.ShowImage(background.rotate(180))

    def draw_text(self):
        size = (320, 240)
        background = Image.new("RGB", size, (240, 255, 180))
        draw = ImageDraw.Draw(background)
        y_offset = self.current_y - self.scroll_offset
        for line in self.current_lines:
            draw.text((5, y_offset), line, fill=self.current_color, font=self.current_font)
            y_offset += fontsize
        self.disp.ShowImage(background.rotate(180))

    def refresh(self):
        if self.current_message:
            self.draw_text()

    def show_list(self, items, selected_index):
        self.in_menu = True
        size = (320, 240)
        background = Image.new("RGB", size, (240, 255, 180))
        draw = ImageDraw.Draw(background)
        font = ImageFont.truetype(os.path.join(os.path.dirname(__file__), '../Font/Font02.ttf'), fontsize)

        for i, item in enumerate(items):
            color = "RED" if i == selected_index else "BLACK"
            draw.text((10, 20 + i * 30), item, fill=color, font=font)

        self.disp.ShowImage(background.rotate(180))
    
    def clear(self):
        self.disp.reset()
        self.disp.clear()


class ListMenu:
    def __init__(self, display):
        self.display = display
        self.items = ["Get sniffer list", "Get access point list", "Create recording", "Exit"]
        self.selected_index = 0

    def navigate(self, direction="UP"):
        if direction == "UP":
            self.selected_index = (self.selected_index - 1) % len(self.items)
            sleep(0.1)
        elif direction == "DOWN":
            self.selected_index = (self.selected_index + 1) % len(self.items)
            sleep(0.1)
        elif direction == "NONE":
            self.selected_index = self.selected_index
            sleep(0.1)
        self.display.show_list(self.items, self.selected_index)

    def select(self):
        selected_item = self.items[self.selected_index]
        #self.display.show_message(f"Selected: {selected_item}")
        return selected_item

    def refuse(self):
        self.display.show_message("Action Refused!")


class ButtonHandler:
    def __init__(self, menu, display):
        self.menu = menu
        self.display = display
        GPIO.setmode(GPIO.BCM)
        for pin in BUTTON_PINS.keys():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

    def listen(self):
        while True:
            for pin, action in BUTTON_PINS.items():
                if GPIO.input(pin) == GPIO.HIGH:
                    if action in ["UP", "DOWN"] and display.in_menu == True:
                        self.menu.navigate(action)
                    elif action in ["UP", "DOWN"] and display.scrollable == True:
                        if action == "UP":
                            self.display.scroll_offset -= 20
                            self.display.refresh()
                        elif action == "DOWN":
                            self.display.scroll_offset += 20
                            self.display.refresh()
                    elif action == "ACCEPT":
                        selected = self.menu.select()
                        if selected == "Get sniffer list":
                            self.display.show_message(client.get_sniffer_list())
                        elif selected == "Get access point list":
                            self.display.show_message(client.get_access_point_list())
                        elif selected == "Create recording":
                            self.display.show_message(client.create_recording())
                        elif selected == "Exit":
                            self.cleanup()
                            return
                    elif action == "REFUSE" and display.in_menu == False:
                        self.menu.navigate("NONE")
                        display.scroll_offset = 0

    def cleanup(self):
        display.clear()
        sys.exit()

if __name__ == "__main__":
    try:
        display = Display()
        menu = ListMenu(display)
        button_handler = ButtonHandler(menu, display)
        client = client.Client()
        if not client.is_connected():
            display.show_message("Failed to connect to server!", "RED")
            sleep(3)
            display.clear()
            sys.exit()
        else:
            display.show_message("Connected to sniffer!", "GREEN")
            sleep(2)

        menu.navigate()
        button_handler.listen()
    except KeyboardInterrupt:
        GPIO.cleanup()
        sys.exit()
